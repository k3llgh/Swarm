"""
nano_swarm/triage/nano.py
──────────────────────────
Triage Nano — the quality gate between specialist nanos and the report.

Applies the invalidation library to every finding using a fixed five-step
protocol. The order matters: the cheapest rejection check runs first so
expensive reasoning (economics, impact modelling) is only performed when
the finding has survived the prior steps.

Step order (EG first — cheapest, most common rejection):
  1. EG  — does an existing guard already block this attack?
  2. UP  — are the preconditions realistic in practice?
  3. US  — can the vulnerable state actually be reached?
  4. CP  — is the attack economically profitable after all costs?
           (uses real numbers from cost_accounting.py, not heuristics)
  5. DI / SH / IM — is the impact real or theoretical?

Decision outputs:
  ACCEPT       → confirmed finding, routes to output
  REJECT       → false positive, logged for Loop 1 learning
  DOWNGRADE    → finding valid but severity reduced
  NEEDS_JURY   → uncertain; routes to adversarial jury debate

Principle 1 (Nano Trust Minimisation):
  Triage is biased toward REJECT. A finding must survive all five steps.
  Every rejection is training signal (Loop 1) not wasted work.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from ..llm_client import get_client
from .invalidation_library import INVALIDATION_LIBRARY
from ..specialist_nanos.base import Finding

log = logging.getLogger(__name__)


# ── System prompt ─────────────────────────────────────────────────────────────

_SYSTEM = f"""\
You are the Triage Nano in a blockchain security auditing system.

YOUR JOB: apply the invalidation library to every finding and decide whether
it is real. Be a constructive sceptic — reject confidently when a reason
clearly applies, but do not dismiss findings without evidence.

{INVALIDATION_LIBRARY}

FIVE-STEP PROTOCOL (apply in this exact order — stop at first clear rejection):
  Step 1 — EXISTING GUARD (EG-1 through EG-5)
    Does existing code already prevent this attack?
    If yes → REJECT immediately. This is the cheapest check.

  Step 2 — UNREALISTIC PRECONDITIONS (UP-1 through UP-5)
    Are the attack's prerequisites achievable in practice?

  Step 3 — UNREACHABLE STATE (US-1 through US-4)
    Can the vulnerable state actually occur?

  Step 4 — ECONOMICS (CP-1 through CP-5)
    Is the attack profitable after all costs?
    Use the cost_accounting numbers provided — do not estimate.

  Step 5 — IMPACT (DI-1 through DI-4, SH-1 through SH-3, IM-1 through IM-4)
    Is the impact real and significant, or theoretical/dust?

DECISION RULES:
  ACCEPT:      all five steps find no applicable invalidation reason
  REJECT:      any step finds a clearly applicable reason (confidence ≥ 0.80)
  DOWNGRADE:   finding is real but severity is lower than claimed
               (e.g. impact bounded by a rate limiter — HIGH → MED)
  NEEDS_JURY:  genuine uncertainty, competing evidence, or severity delta > 1 level

OUTPUT: a single JSON object only. No markdown. No preamble.
{{
  "finding_id":          "string",
  "decision":            "ACCEPT | REJECT | DOWNGRADE | NEEDS_JURY",
  "final_severity":      "CRIT | HIGH | MED | LOW | null",
  "confidence":          0.0,
  "step_results": {{
    "EG":      {{"triggered": false, "code": null, "note": ""}},
    "UP":      {{"triggered": false, "code": null, "note": ""}},
    "US":      {{"triggered": false, "code": null, "note": ""}},
    "CP":      {{"triggered": false, "code": null, "note": ""}},
    "DI_SH_IM":{{"triggered": false, "code": null, "note": ""}}
  }},
  "invalidation_codes":  [],
  "accept_note":         "string if ACCEPT — why all steps cleared",
  "reject_note":         "string if REJECT — which step fired and why",
  "downgrade_note":      "string if DOWNGRADE — what bounded the impact",
  "jury_flag":           "string if NEEDS_JURY — what is genuinely uncertain"
}}
"""


# ── Triage nano ───────────────────────────────────────────────────────────────

class TriageNano:
    """
    Applies the invalidation library to individual findings.
    Called by the pipeline orchestrator after the specialist nano fan-out.
    """

    def triage(
        self,
        finding: Finding,
        protocol_context: dict,
        cost_accounting: Optional[dict] = None,
    ) -> dict:
        """
        Triage one finding.

        Args:
            finding:          the Finding produced by a specialist nano
            protocol_context: known limitations, documented behaviours, etc.
            cost_accounting:  output from cost_accounting.calculate_attack_cost()
                              — if provided, Step 4 uses real numbers

        Returns:
            Triage verdict dict (matches the JSON schema above).
        """
        user = self._build_prompt(finding, protocol_context, cost_accounting)

        try:
            client = get_client()
            response = client.chat(
                system=_SYSTEM,
                user=user,
                max_tokens=1200,
                temperature=0.1,
            )
            verdict = response.as_json()
            verdict["finding_id"] = finding.finding_id    # always override
            return verdict

        except Exception as exc:
            log.error("Triage error for %s: %s", finding.finding_id, exc)
            # On error: route to jury rather than auto-accept or auto-reject
            return {
                "finding_id":    finding.finding_id,
                "decision":      "NEEDS_JURY",
                "final_severity": finding.severity,
                "confidence":    0.5,
                "step_results":  {},
                "invalidation_codes": [],
                "jury_flag":     f"Triage API error: {exc}",
            }

    def triage_batch(
        self,
        findings: list[Finding],
        protocol_context: dict,
        cost_results: Optional[dict] = None,
    ) -> list[dict]:
        """
        Triage a list of findings sequentially.
        cost_results is a dict keyed by finding_id → cost_accounting output.
        """
        verdicts: list[dict] = []
        for finding in findings:
            cost = cost_results.get(finding.finding_id) if cost_results else None
            verdict = self.triage(finding, protocol_context, cost)
            verdicts.append(verdict)
            time.sleep(0.2)    # gentle rate limiting
        return verdicts

    # ── Private ───────────────────────────────────────────────────────────────

    def _build_prompt(
        self,
        finding: Finding,
        protocol_context: dict,
        cost_accounting: Optional[dict],
    ) -> str:
        import json

        finding_json = json.dumps(finding.to_dict(), indent=2)

        cost_section = ""
        if cost_accounting:
            cost_section = (
                "\nCost Accounting (deterministic — use these numbers for Step 4):\n"
                f"  Extractable value: ${cost_accounting.get('extractable_value_usd', '?'):,.0f}\n"
                f"  Gas cost:          ${cost_accounting.get('gas_cost_usd', '?'):,.2f}\n"
                f"  Flash loan fee:    ${cost_accounting.get('flashloan_fee_usd', '?'):,.2f}\n"
                f"  Slippage:          ${cost_accounting.get('slippage_cost_usd', '?'):,.2f}\n"
                f"  Net profit:        ${cost_accounting.get('net_profit_usd', '?'):,.0f}\n"
                f"  Profitable:        {cost_accounting.get('profitable', '?')}\n"
                f"  Auto-codes:        {cost_accounting.get('applicable_invalidation_codes', [])}\n"
            )

        known_limits = protocol_context.get("known_limitation_flags", [])
        limits_section = (
            "\n".join(f"  - {l}" for l in known_limits)
            if known_limits else "  none documented"
        )

        return (
            f"Finding to triage:\n{finding_json}\n"
            f"{cost_section}\n"
            f"Protocol known limitations / documented behaviours:\n{limits_section}\n\n"
            "Apply all five triage steps in order and output the verdict JSON."
        )
