"""
nano_swarm/jury/orchestrator.py
─────────────────────────────────
Jury — adversarial debate for contested findings.

The jury is invoked only when triage is uncertain or when severity
differs significantly between the nano's claim and triage's verdict.

Protocol (three rounds):
  Round 1 — Prosecution: DeepSeek V3 argues FOR the finding being valid
  Round 2 — Defense:     DeepSeek V3 argues AGAINST using the invalidation library
  Round 3 — Verdict:     DeepSeek V3 weighs both arguments and decides

Human escalation (Trigger H-1, H-2, H-3):
  H-1: jury severity differs from triage severity by more than one level
  H-2: finding class matches no existing checklist row (genuinely novel)
  H-3: jury cannot reach confident verdict after three rounds

The jury is expensive (three LLM calls per finding) and is used sparingly.
High-confidence triage accepts / rejects skip the jury entirely.

Principle 2 (Human Trust Maximisation):
  Human escalation findings are never auto-rejected. They are held in
  data/reports/{audit_id}/human_queue.json with a 24-hour SLA.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from ..llm_client import get_client
from ..specialist_nanos.base import Finding
from ..triage.invalidation_library import INVALIDATION_LIBRARY

log = logging.getLogger(__name__)

# Severity levels as integers for delta calculation
_SEVERITY_RANK = {"CRIT": 3, "HIGH": 2, "MED": 1, "LOW": 0}


class JuryOrchestrator:
    """
    Runs the three-round adversarial debate for a single finding.
    """

    def adjudicate(
        self,
        finding: Finding,
        triage_verdict: dict,
        protocol_context: dict,
        cost_accounting: Optional[dict] = None,
    ) -> dict:
        """
        Run prosecution → defense → verdict for one finding.

        Returns a jury verdict dict with keys:
          verdict:          CONFIRMED | REJECTED | DOWNGRADED | NEEDS_EXTERNAL_REVIEW
          final_severity:   CRIT | HIGH | MED | LOW | null
          verdict_reasoning: one-paragraph explanation
          prosecution_point: strongest argument for
          defense_point:     strongest argument against
          triage_was_wrong:  bool
          human_escalation:  bool
          escalation_reason: str (if human_escalation is True)
        """
        context = self._build_context(finding, triage_verdict, protocol_context, cost_accounting)
        client = get_client()

        # Round 1: prosecution
        prosecution = self._round(
            client,
            role="You are arguing that this finding IS a valid, exploitable vulnerability. "
                 "Build the strongest possible case. Cite real exploit analogues, "
                 "checklist row evidence, and economic rationale.",
            context=context,
            max_tokens=600,
        )

        # Round 2: defense
        defense = self._round(
            client,
            role=(
                "You are arguing that this finding should be REJECTED or DOWNGRADED. "
                "Apply the invalidation library aggressively. Challenge the economics, "
                "the preconditions, existing guards, and the reachability of the state.\n\n"
                f"Prosecution argument:\n{prosecution[:500]}"
            ),
            context=context,
            max_tokens=600,
        )

        # Round 3: verdict
        verdict_json = self._verdict_round(client, prosecution, defense, context)

        # Human escalation checks
        claimed_sev = finding.severity
        final_sev = verdict_json.get("final_severity", claimed_sev)
        triage_sev = triage_verdict.get("final_severity", claimed_sev)

        sev_delta = abs(
            _SEVERITY_RANK.get(claimed_sev, 0) - _SEVERITY_RANK.get(final_sev, 0)
        )

        human_escalation = False
        escalation_reason = ""

        if sev_delta > 1:
            human_escalation = True
            escalation_reason = (
                f"Trigger H-1: severity delta = {sev_delta} "
                f"({claimed_sev} claimed → {final_sev} jury verdict)"
            )
        elif verdict_json.get("verdict") == "NEEDS_EXTERNAL_REVIEW":
            human_escalation = True
            escalation_reason = "Trigger H-3: jury could not reach a confident verdict"

        if human_escalation:
            verdict_json["verdict"] = "NEEDS_EXTERNAL_REVIEW"

        return {
            "finding_id":          finding.finding_id,
            "title":               finding.title,
            "checklist_refs":      finding.checklist_refs,
            "fix":                 finding.fix,
            **verdict_json,
            "prosecution_point":   prosecution[:300],
            "defense_point":       defense[:300],
            "triage_was_wrong":    verdict_json.get("verdict") in ("CONFIRMED", "DOWNGRADED")
                                   and triage_verdict.get("decision") in ("REJECT",),
            "human_escalation":    human_escalation,
            "escalation_reason":   escalation_reason,
        }

    # ── Private ───────────────────────────────────────────────────────────────

    def _build_context(
        self,
        finding: Finding,
        triage_verdict: dict,
        protocol_context: dict,
        cost_accounting: Optional[dict],
    ) -> str:
        finding_json = json.dumps(finding.to_dict(), indent=2)
        triage_json  = json.dumps({
            k: triage_verdict[k]
            for k in ("decision", "step_results", "invalidation_codes")
            if k in triage_verdict
        }, indent=2)

        cost_section = ""
        if cost_accounting:
            cost_section = f"\nCost accounting:\n{json.dumps(cost_accounting, indent=2)}\n"

        return (
            f"Finding:\n{finding_json}\n\n"
            f"Triage verdict:\n{triage_json}\n"
            f"{cost_section}\n"
            f"Protocol limitations: {protocol_context.get('known_limitation_flags', [])}\n"
        )

    def _round(self, client, role: str, context: str, max_tokens: int) -> str:
        try:
            resp = client.chat(
                system=f"{role}\n\nInvalidation library for reference:\n{INVALIDATION_LIBRARY[:3000]}",
                user=context,
                max_tokens=max_tokens,
                temperature=0.3,
            )
            return resp.text.strip()
        except Exception as exc:
            log.error("Jury round error: %s", exc)
            return f"[jury round failed: {exc}]"

    def _verdict_round(
        self, client, prosecution: str, defense: str, context: str
    ) -> dict:
        prompt = (
            f"{context}\n\n"
            f"Prosecution argument:\n{prosecution[:500]}\n\n"
            f"Defense argument:\n{defense[:500]}\n\n"
            "Weigh both arguments and output a verdict JSON object only. No markdown.\n"
            "{\n"
            '  "verdict": "CONFIRMED | REJECTED | DOWNGRADED | NEEDS_EXTERNAL_REVIEW",\n'
            '  "final_severity": "CRIT | HIGH | MED | LOW | null",\n'
            '  "verdict_reasoning": "one-paragraph explanation",\n'
            '  "prosecution_won": true\n'
            "}"
        )
        try:
            resp = client.chat(
                system="You are a neutral security jury. Weigh the evidence fairly. Output JSON only.",
                user=prompt,
                max_tokens=400,
                temperature=0.1,
            )
            return resp.as_json()
        except Exception as exc:
            log.error("Jury verdict round error: %s", exc)
            return {
                "verdict":           "NEEDS_EXTERNAL_REVIEW",
                "final_severity":    None,
                "verdict_reasoning": f"Jury verdict round failed: {exc}",
                "prosecution_won":   False,
            }
