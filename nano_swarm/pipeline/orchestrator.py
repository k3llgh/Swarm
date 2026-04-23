"""
nano_swarm/pipeline/orchestrator.py
─────────────────────────────────────
Main audit pipeline. Ties every component together.

Flow:
  1. Code Reader     — extract functions, external calls, state variables
  2. Arch Synthesizer — build protocol mental model + routing plan
  3. Fan-out          — run specialist nanos in parallel on scoped zones
  4. Collect          — gather findings + process lateral routing signals
  5. Cost Accounting  — calculate real attack economics for each finding
  6. Triage           — apply invalidation library (EG→UP→US→CP→DI)
  7. Jury             — adversarial debate for contested findings
  8. Report           — produce structured output

Three trust principles enforced here:
  Principle 1 (Nano Trust Minimisation)
    No specialist nano output consumed directly by another nano.
    Everything passes through this orchestrator.

  Principle 2 (Human Trust Maximisation)
    Three triggers send findings to a human queue, never auto-reject:
      H-1: jury severity delta > 1 level from triage
      H-2: finding class not in any checklist row (novel pattern)
      H-3: jury cannot reach a verdict

  Principle 3 (Code Trust Maximisation)
    CRIT findings with high triage confidence are queued for sandbox
    validation before appearing in the final report.
    No CRIT ships without a passing PoC (when sandbox available).
"""
from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..config import settings
from ..jury.orchestrator import JuryOrchestrator
from ..re_nano.curriculum import build_teaching_context
from ..specialist_nanos.access_control import AccessControlSpecialistNano
from ..specialist_nanos.base import BaseSpecialistNano, Finding, NanoResult
from ..specialist_nanos.reentrancy_master import ReentrancyMasterNano
from ..tools.cost_accounting import calculate_attack_cost, quick_sanity_check
from ..triage.nano import TriageNano

log = logging.getLogger(__name__)

# Routing thresholds
_SEVERITY_RANK         = {"CRIT": 3, "HIGH": 2, "MED": 1, "LOW": 0}
_TRIAGE_CONF_FLOOR     = settings.triage_confidence_floor  # below → jury
_CRIT_JURY_THRESHOLD   = settings.crit_jury_threshold      # CRIT below → jury
_SEVERITY_JURY_DELTA   = 1                                  # delta above → jury


# ── Audit input / output ──────────────────────────────────────────────────────

@dataclass
class AuditInput:
    """Everything the pipeline needs to audit one contract."""
    contract_code: str
    chain:         str                    # ethereum | solana | sui | bitcoin
    protocol_name: str          = "unknown"
    tvl_usd:       Optional[float] = None
    gas_price_gwei: float       = 30.0
    protocol_docs:  str         = ""      # README / NatSpec text


@dataclass
class AuditReport:
    """Structured output from one complete audit run."""
    protocol_name:      str
    chain:              str
    findings:           list[dict] = field(default_factory=list)   # accepted
    rejected:           list[dict] = field(default_factory=list)   # triage/jury rejected
    jury_cases:         list[dict] = field(default_factory=list)   # all jury verdicts
    human_queue:        list[dict] = field(default_factory=list)   # H-1/H-2/H-3
    metadata:           dict       = field(default_factory=dict)

    def save(self, path: Path) -> None:
        """Persist report to JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as fh:
            json.dump({
                "protocol_name": self.protocol_name,
                "chain":         self.chain,
                "findings":      self.findings,
                "rejected":      self.rejected,
                "jury_cases":    self.jury_cases,
                "human_queue":   self.human_queue,
                "metadata":      self.metadata,
            }, fh, indent=2)
        log.info("Report saved → %s", path)

    def summary(self) -> str:
        by_sev: dict[str, int] = {}
        for f in self.findings:
            s = f.get("final_severity") or f.get("severity", "?")
            by_sev[s] = by_sev.get(s, 0) + 1

        lines = [
            "",
            "=" * 60,
            f"AUDIT REPORT: {self.protocol_name} [{self.chain.upper()}]",
            "=" * 60,
            f"Confirmed findings : {len(self.findings)}",
        ]
        for sev in ("CRIT", "HIGH", "MED", "LOW"):
            if by_sev.get(sev):
                lines.append(f"  {sev:<6} {by_sev[sev]}")
        lines += [
            f"Triage rejected    : {len(self.rejected)}",
            f"Jury cases         : {len(self.jury_cases)}",
            f"Human queue (SLA)  : {len(self.human_queue)}",
            "-" * 60,
        ]
        for f in self.findings:
            sev   = f.get("final_severity") or f.get("severity", "?")
            title = f.get("title", "?")
            refs  = ", ".join((f.get("checklist_refs") or [])[:2])
            lines.append(f"  [{sev}] {title}  ({refs})")
        lines.append("=" * 60)
        return "\n".join(lines)


# ── Pipeline orchestrator ─────────────────────────────────────────────────────

class PipelineOrchestrator:
    """
    Coordinates the full audit pipeline.
    Instantiate once; call audit() for each contract.
    """

    def __init__(self) -> None:
        # Register specialist nanos here — add new ones as they are built
        self.nanos: list[BaseSpecialistNano] = [
            ReentrancyMasterNano(),
            AccessControlSpecialistNano(),
        ]
        self.triage = TriageNano()
        self.jury   = JuryOrchestrator()

    def audit(self, inp: AuditInput) -> AuditReport:
        """Run a complete audit and return a structured report."""
        report = AuditReport(protocol_name=inp.protocol_name, chain=inp.chain)
        t0 = time.time()

        log.info("Auditing %s [%s]", inp.protocol_name, inp.chain)

        # Step 1: code reading (stub — one zone = full contract)
        zones = self._code_reader(inp)

        # Step 2: architecture synthesis (stub — route all zones to all nanos)
        routing = self._arch_synthesizer(inp, zones)

        # Step 3: parallel fan-out to specialist nanos
        log.info("Fan-out: %d routes", len(routing["routes"]))
        nano_results = self._fan_out(inp, routing)

        # Step 4: collect + deduplicate findings; process lateral signals
        raw_findings = self._collect(nano_results, inp, routing)
        log.info("Raw findings: %d", len(raw_findings))

        # Step 5: cost accounting
        cost_results: dict[str, dict] = {}
        if inp.tvl_usd:
            for f in raw_findings:
                cost_results[f.finding_id] = quick_sanity_check(
                    f.severity, inp.tvl_usd, inp.chain, inp.gas_price_gwei
                )

        # Step 6: triage
        protocol_ctx = {
            "known_limitation_flags": routing.get("known_limitations", []),
        }
        triage_verdicts = self.triage.triage_batch(raw_findings, protocol_ctx, cost_results)

        # Step 7: route each verdict to output / reject / jury
        for finding, verdict in zip(raw_findings, triage_verdicts):
            cost = cost_results.get(finding.finding_id)
            self._route(finding, verdict, protocol_ctx, cost, report)

        # Sort confirmed findings by severity
        report.findings.sort(
            key=lambda f: -_SEVERITY_RANK.get(f.get("final_severity") or "", 0)
        )

        report.metadata = {
            "duration_seconds":      round(time.time() - t0, 1),
            "nanos":                 [n.NANO_NAME for n in self.nanos],
            "raw_findings":          len(raw_findings),
            "triage_reject_rate":    round(
                len(report.rejected) / max(len(raw_findings), 1), 2
            ),
            "jury_cases":            len(report.jury_cases),
            "human_escalation_rate": round(
                len(report.human_queue) / max(len(raw_findings), 1), 3
            ),
        }

        log.info(report.summary())
        return report

    # ── Step 1: Code Reader (stub) ────────────────────────────────────────────
    # Replace with Code Reader Nano (Phase 2) once trained.

    def _code_reader(self, inp: AuditInput) -> list[dict]:
        import re
        fn_patterns = [
            r"function\s+(\w+)\s*\(",
            r"pub fn\s+(\w+)\s*\(",
            r"public\s+fun\s+(\w+)\s*\(",
        ]
        names: list[str] = []
        for pat in fn_patterns:
            names.extend(re.findall(pat, inp.contract_code))

        return [{
            "zone_id":     "zone_001",
            "scoped_code": inp.contract_code,
            "functions":   list(set(names))[:20],
            "phase_2":     True,
        }]

    # ── Step 2: Architecture Synthesizer (stub) ───────────────────────────────
    # Replace with Architecture Synthesizer Nano (Phase 2) once trained.

    def _arch_synthesizer(self, inp: AuditInput, zones: list[dict]) -> dict:
        routes = [
            {
                "nano":       nano.NANO_NAME,
                "zone_id":    zone["zone_id"],
                "zone":       zone,
                "focus_hint": f"Full {inp.chain} audit",
            }
            for zone in zones
            for nano in self.nanos
            if inp.chain in nano.SUPPORTED_CHAINS
        ]
        return {"protocol_type": "unknown", "routes": routes, "known_limitations": []}

    # ── Step 3: parallel fan-out ──────────────────────────────────────────────

    def _fan_out(self, inp: AuditInput, routing: dict) -> list[NanoResult]:
        results: list[NanoResult] = []
        routes = routing.get("routes", [])

        def _run(route: dict) -> NanoResult:
            nano = self._get_nano(route["nano"])
            if not nano:
                return NanoResult(nano_name=route["nano"], zone_id=route["zone_id"],
                                  chain=inp.chain)
            zone = route["zone"]

            # Fetch RE Nano teaching context for this zone
            try:
                ctx = build_teaching_context(
                    nano_target=route["nano"],
                    zone_id=zone["zone_id"],
                    zone_code=zone["scoped_code"],
                    chain=inp.chain,
                    vuln_class=_nano_to_vuln_class(route["nano"]),
                    top_k=4,
                )
            except Exception:
                ctx = None

            return nano.analyse(
                zone_id=zone["zone_id"],
                scoped_code=zone["scoped_code"],
                chain=inp.chain,
                code_reader=zone,
                arch_context={"focus_hint": route.get("focus_hint", "")},
                teaching_context=ctx,
            )

        with ThreadPoolExecutor(max_workers=min(len(routes), 4)) as pool:
            futures = {pool.submit(_run, route): route for route in routes}
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=120)
                    results.append(result)
                    log.info(
                        "  %s/%s: %d finding(s), %d lateral(s)%s",
                        result.nano_name, result.zone_id,
                        len(result.findings), len(result.lateral_signals),
                        f" [err: {result.error[:60]}]" if result.error else "",
                    )
                except Exception as exc:
                    log.error("  Fan-out error: %s", exc)

        return results

    # ── Step 4: collect + deduplicate ─────────────────────────────────────────

    def _collect(
        self,
        results: list[NanoResult],
        inp: AuditInput,
        routing: dict,
    ) -> list[Finding]:
        """Collect findings, deduplicate by title+chain, process lateral signals."""
        all_findings: list[Finding] = []
        seen: set[str] = set()
        lateral_signals: list = []

        for result in results:
            for finding in result.findings:
                key = f"{finding.title.lower()[:50]}::{finding.chain}"
                if key not in seen:
                    seen.add(key)
                    all_findings.append(finding)
            lateral_signals.extend(result.lateral_signals)

        # Process lateral routing signals — one round, no re-synthesis
        if lateral_signals:
            log.info("Processing %d lateral signal(s)…", len(lateral_signals))
            zone_map = {r["zone_id"]: r["zone"] for r in routing.get("routes", [])}
            for signal in lateral_signals:
                nano = self._get_nano(signal.route_to)
                zone = zone_map.get(signal.zone_id)
                if not nano or not zone:
                    continue
                try:
                    result = nano.analyse(
                        zone_id=signal.zone_id,
                        scoped_code=zone["scoped_code"],
                        chain=inp.chain,
                        code_reader=zone,
                        arch_context={"focus_hint": signal.reason},
                    )
                    for finding in result.findings:
                        key = f"{finding.title.lower()[:50]}::{finding.chain}"
                        if key not in seen:
                            seen.add(key)
                            all_findings.append(finding)
                except Exception as exc:
                    log.error("Lateral signal error (%s): %s", signal.route_to, exc)

        return all_findings

    # ── Step 7: routing ───────────────────────────────────────────────────────

    def _route(
        self,
        finding: Finding,
        verdict: dict,
        protocol_ctx: dict,
        cost: Optional[dict],
        report: AuditReport,
    ) -> None:
        """Route a triage verdict to the appropriate bucket."""
        decision   = verdict.get("decision", "REJECT")
        confidence = float(verdict.get("confidence", 0.5))
        final_sev  = verdict.get("final_severity")
        flags      = verdict.get("jury_flag")

        # Annotate the verdict with finding metadata for the report
        verdict.update({
            "title":          finding.title,
            "exploit_path":   finding.exploit_path,
            "checklist_refs": finding.checklist_refs,
            "fix":            finding.fix,
            "evidence":       finding.evidence,
            "nano":           finding.nano,
        })
        if cost:
            verdict["cost_accounting"] = cost

        needs_jury = (
            decision == "NEEDS_JURY"
            or bool(flags)
            or (decision == "REJECT" and confidence < _TRIAGE_CONF_FLOOR)
            or (finding.severity == "CRIT" and confidence < _CRIT_JURY_THRESHOLD)
            or abs(
                _SEVERITY_RANK.get(finding.severity, 0) -
                _SEVERITY_RANK.get(final_sev or finding.severity, 0)
            ) > _SEVERITY_JURY_DELTA
        )

        if needs_jury:
            jury_result = self.jury.adjudicate(finding, verdict, protocol_ctx, cost)
            report.jury_cases.append(jury_result)
            if jury_result.get("human_escalation"):
                report.human_queue.append(jury_result)
            elif jury_result.get("verdict") in ("CONFIRMED", "DOWNGRADED"):
                report.findings.append(jury_result)
            else:
                report.rejected.append(jury_result)
        elif decision == "REJECT" and confidence >= _TRIAGE_CONF_FLOOR:
            report.rejected.append(verdict)
        else:
            report.findings.append(verdict)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_nano(self, name: str) -> Optional[BaseSpecialistNano]:
        return next((n for n in self.nanos if n.NANO_NAME == name), None)


def _nano_to_vuln_class(nano_name: str) -> str:
    return {
        "ReentrancyMaster":        "reentrancy",
        "AccessControlSpecialist": "access-control",
    }.get(nano_name, "")
