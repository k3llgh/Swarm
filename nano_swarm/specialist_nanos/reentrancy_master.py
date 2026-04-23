"""
nano_swarm/specialist_nanos/reentrancy_master.py
─────────────────────────────────────────────────
Reentrancy Master — detects all reentrancy classes across ETH / SOL / SUI.
Bitcoin is excluded: it is not Turing-complete and reentrancy is impossible.

Adversarial posture: assume the vulnerability exists, then look for evidence
to disprove it. If a clear disproof cannot be found, emit a finding.

Covered vulnerability classes:
  Ethereum:
    - Standard CEI violation (state mutation after external call)
    - Cross-function reentrancy (guard on A, shared state with B)
    - Deferred health check (solvency checked after external callback)
    - Read-only reentrancy (view function used as oracle during pool callback)
    - ERC777 / ERC677 hook reentrancy (non-standard token callbacks)
    - msg.value reuse in multicall loops

  Solana:
    - Cross-program reentrancy via CPI (outbound CPI calls back before state final)
    - Stale data after CPI (Anchor does NOT auto-reload — missing reload()? after CPI)
    - Signer pass-through to unvetted program

  Sui Move:
    - return-vs-abort after mutation (return commits state; abort rolls back — Panther)
    - PTB intermediate state exploitation
    - Hot potato misrouting (consumed but value routed incorrectly)
"""
from __future__ import annotations

import logging

from .base import BaseSpecialistNano, Finding, LateralSignal, NanoResult

log = logging.getLogger(__name__)

# ── System prompt ─────────────────────────────────────────────────────────────

_BASE_SYSTEM = """\
You are the Reentrancy Master, a specialist blockchain security auditor.

YOUR ONLY JOB: detect reentrancy vulnerabilities. Ignore all other bug classes.

ADVERSARIAL POSTURE:
  Assume reentrancy exists — then try to disprove it.
  If you cannot clearly disprove it, emit a finding.

KEY PRINCIPLES:
  - A nonReentrant guard on function A does NOT protect function B
    that shares the same state mapping — cross-function path is still open.
  - Deferred health checks (solvency checked AFTER an external call) are
    equivalent to reentrancy in impact — treat them the same way.
  - View functions used as price oracles during pool callbacks are
    read-only reentrancy vectors — the oracle sees stale state.

OUTPUT: a JSON array of findings. Return [] if the zone is definitely clear.
Do NOT output any text outside the JSON array.

FINDING SCHEMA (all fields required):
[
  {
    "finding_id":    "RM-NNN",
    "title":         "short title (one line)",
    "class":         "standard | cross-function | deferred-health-check | read-only | ERC777-hook | value-reuse | CPI | stale-after-CPI | return-vs-abort",
    "chain":         "ethereum | solana | sui",
    "severity":      "CRIT | HIGH | MED | LOW",
    "stealth":       "HIGH | MED | LOW",
    "confidence":    0.0,
    "evidence": {
      "vulnerable_function":      "name",
      "external_call_line":       "line or description",
      "state_mutation_after_call": true,
      "guard_present":             false,
      "guard_effective":           false,
      "guard_frame":               "which function has the guard (may differ from vulnerable)",
      "shared_state_variable":    "variable that can be read stale",
      "reentry_entry_point":      "which function attacker re-enters"
    },
    "exploit_path":   "numbered steps",
    "checklist_refs": ["E-P2-10"],
    "fix":            "concrete fix",
    "lateral_routing_signal": null
  }
]
"""

_CHAIN_ADDENDUM: dict[str, str] = {
    "ethereum": """
ETHEREUM-SPECIFIC PATTERNS:
  - CEI: every state mutation must be BEFORE the external call (transfer, call{value:…}, low-level)
  - Cross-function: guard on withdraw() does not cover borrow() sharing the same balances mapping
  - Deferred: healthFactor / solvency checked after external call → Euler Finance $197M pattern (E-P2-11)
  - Read-only: Curve get_virtual_price() called as oracle during a pool callback → E-P1-06, E-P3-12
  - ERC777: tokensToSend hook fires before balance updated → dForce $25M (E-P1-13)
  - ERC677: transferAndCall onTokenTransfer fires mid-transfer → Ola Finance $3.6M
  - Value reuse: msg.value credited N times in a multicall loop → E-P2-14
  Checklist refs: E-P2-10, E-P2-11, E-P2-12, E-P2-13, E-P2-14, E-P1-06, E-P1-08, E-P1-13
""",
    "solana": """
SOLANA-SPECIFIC PATTERNS:
  - CPI cross-program reentrancy: an outbound CPI can call back into this program
    before all state mutations on shared accounts complete (S-P2-09)
  - Stale data after CPI: Anchor does NOT auto-reload account data after a CPI.
    If ctx.accounts.vault is read after a CPI that mutated it, the value is stale.
    Missing reload()? immediately after any mutating CPI = FINDING (S-P5-07, S-A0-04)
  - Signer pass-through: invoke_signed passes PDA authority to an unvetted program (S-P2-04)
""",
    "sui": """
SUI MOVE-SPECIFIC PATTERNS:
  - return-vs-abort: `return` commits all mutations; `abort` rolls them back.
    Any &mut function that mutates state THEN uses `return` on an error path
    permanently commits the mutation. Only `abort` is safe on error paths.
    Classic: order removed from table → validation fails → return → deletion committed (Panther)
    Checklist refs: S-A0-02, S-P3-01, S-P3-02, S-P1-05
  - PTB intermediate state: a multi-step PTB can read stale state between commands
  - Hot potato misrouting: potato consumed but value sent to wrong recipient
""",
    "bitcoin": "Bitcoin is not Turing-complete. Reentrancy is impossible. Return [].",
}


# ── Nano implementation ───────────────────────────────────────────────────────

class ReentrancyMasterNano(BaseSpecialistNano):

    NANO_NAME = "ReentrancyMaster"
    VULNERABILITY_CLASSES = [
        "reentrancy",
        "CEI-violation",
        "deferred-health-check",
        "cross-function-reentrancy",
        "read-only-reentrancy",
        "return-vs-abort",
    ]
    SUPPORTED_CHAINS = ["ethereum", "solana", "sui"]

    def _build_system_prompt(self, chain: str) -> str:
        return _BASE_SYSTEM + _CHAIN_ADDENDUM.get(chain, "")

    def _parse_response(self, raw_text: str, result: NanoResult, chain: str) -> NanoResult:
        # Capture any reasoning that precedes the JSON block
        if "```" in raw_text:
            result.reasoning_trace = raw_text.split("```")[0].strip()[:400]

        raw_findings = self._extract_json(raw_text)

        for i, raw in enumerate(raw_findings):
            if not isinstance(raw, dict) or not raw.get("title"):
                continue

            raw.setdefault("finding_id", f"RM-{i+1:03d}")

            lateral = None
            if raw.get("lateral_routing_signal") and isinstance(raw["lateral_routing_signal"], dict):
                ls = raw["lateral_routing_signal"]
                lateral = LateralSignal(
                    route_to=ls.get("route_to", ""),
                    zone_id=ls.get("zone_id", result.zone_id),
                    reason=ls.get("reason", ""),
                )

            confidence = float(raw.get("confidence", 0.5))
            severity = raw.get("severity", "MED")

            # Conservative demotion: low confidence on a CRIT claim → HIGH
            if confidence < 0.5 and severity == "CRIT":
                severity = "HIGH"

            finding = Finding(
                nano=self.NANO_NAME,
                finding_id=raw["finding_id"],
                title=raw.get("title", ""),
                vuln_class=raw.get("class", "reentrancy"),
                chain=raw.get("chain", chain),
                severity=severity,
                stealth=raw.get("stealth", "MED"),
                confidence=confidence,
                evidence=raw.get("evidence", {}),
                exploit_path=raw.get("exploit_path", ""),
                checklist_refs=raw.get("checklist_refs", []),
                fix=raw.get("fix", ""),
                lateral=lateral,
            )
            result.add_finding(finding)

        if not result.findings:
            result.zones_cleared.append(result.zone_id)

        return result
