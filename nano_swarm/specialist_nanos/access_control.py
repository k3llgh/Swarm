"""
nano_swarm/specialist_nanos/access_control.py
──────────────────────────────────────────────
Access Control Specialist — authorisation failures across all four chains.

Adversarial posture: assume every function is callable by an attacker
until explicitly proven otherwise by code-level checks.

Covered vulnerability classes:
  Ethereum:
    - Initialiser front-run (E-P4-01)
    - Missing _disableInitializers() on implementation (E-P4-02)
    - UUPS _authorizeUpgrade unrestricted (E-P4-03)
    - Single-step ownership transfer (E-P4-04)
    - Role self-escalation (E-P4-05)
    - No timelock on critical parameters (E-P4-06)
    - Trusted-zero default (Nomad $190M — E-P4-08)
    - Storage collision (E-P1-10, E-P2-01)
    - Governance: flash-loan voting, quorum manipulation, proposal composition (E-P9-*)

  Solana (Frank Castle 6-step validation):
    - Missing owner check (S-P0-02) — Cashio $48M
    - Missing signer check (S-P0-03) — Wormhole $320M
    - Arbitrary CPI (S-P2-01)
    - Non-canonical PDA bump (S-P3-01)
    - Type cosplay (S-P0-05)
    - Reinitialization via init_if_needed (S-P5-04)
    - PDA seed collision (S-P3-04)
    - Duplicate mutable accounts (S-A0-08)

  Sui Move:
    - ctx.sender() confusion behind shared objects (S-A0-01)
    - public(package) + entry bypass (S-P0-07)
    - Caller param spoofing (S-P1-09)
    - Phantom type escalation (S-P1-10)
    - UID type swapping (S-P2-09)
    - key+store free transfer / freeze (S-A0-08)
    - OTW forgery (S-A0-09)

  Bitcoin:
    - Coinbase staking TX accepted without null prevout check (B-A0-01, B-P2-01)
    - Slashing window bypass via maturity delay (B-A0-04, B-P5-01)
    - Script type mismatch (B-A0-05, B-P4-02)
    - Confirmation threshold insufficient for coinbase (B-P6-01)
"""
from __future__ import annotations

import logging

from .base import BaseSpecialistNano, Finding, LateralSignal, NanoResult

log = logging.getLogger(__name__)

# ── System prompt ─────────────────────────────────────────────────────────────

_BASE_SYSTEM = """\
You are the Access Control Specialist, a blockchain security auditor.

YOUR ONLY JOB: find authorisation and privilege boundary violations.
Ignore all other bug classes.

ADVERSARIAL POSTURE:
  Assume every function is callable by an attacker.
  Then look for evidence that conclusively proves otherwise.
  A check that verifies identity (key match) but not authority (is_signer) is incomplete.

OUTPUT: a JSON array of findings. Return [] if the zone is clearly secure.
Do NOT output any text outside the JSON array.

FINDING SCHEMA (all fields required):
[
  {
    "finding_id":    "AC-NNN",
    "title":         "short title",
    "class":         "missing_check | escalation | initializer | upgrade | storage | governance | CPI | PDA | phantom_type | ctx_sender | OTW | coinbase",
    "chain":         "ethereum | solana | sui | bitcoin",
    "severity":      "CRIT | HIGH | MED | LOW",
    "stealth":       "HIGH | MED | LOW",
    "confidence":    0.0,
    "evidence": {
      "vulnerable_function":  "name",
      "missing_check":        "description of the absent check",
      "attacker_capability":  "what an attacker can do without the check",
      "existing_guards":      ["checks that ARE present"],
      "guard_bypass_path":    "how existing guards are circumvented",
      "six_step_result": {
        "key":           "present | missing | N/A",
        "owner":         "present | missing | N/A",
        "signer":        "present | missing | N/A",
        "writable":      "present | missing | N/A",
        "discriminator": "present | missing | N/A",
        "data":          "present | missing | N/A"
      }
    },
    "exploit_path":   "numbered attack steps",
    "checklist_refs": ["S-P0-03"],
    "fix":            "concrete fix",
    "lateral_routing_signal": null
  }
]
"""

_CHAIN_ADDENDUM: dict[str, str] = {
    "ethereum": """
ETHEREUM ACCESS CONTROL PATTERNS:
  Initialiser:
    - E-P4-01: deployer + initialize() not in same tx → front-runnable
    - E-P4-02: _disableInitializers() absent in implementation constructor → re-initializable
    - E-P4-03: _authorizeUpgrade() not restricted to multisig/timelock
    - E-P4-04: single-step transferOwnership → wrong address accepted immediately
    - E-P4-05: role can grantRole(SAME_OR_HIGHER_ROLE) without timelock
    - E-P4-06: critical params (fee, oracle, pause) changeable with no timelock delay

  Trusted-zero / storage:
    - E-P4-08: zero bytes/address accepted as valid proven root (Nomad $190M pattern)
    - E-P1-10 + E-P2-01: proxy admin slot overlaps implementation variable at slot 0
    - E-P4-09: storage layout shifts after upgrade (inherited contract reordering)
    - E-P4-10: new functions added in upgrade bypass guards from prior version

  Governance:
    - E-P1-09: flash-loan voting — snapshot at execution block not proposal creation
    - E-P9-01: proposal dependency — action A writes state action B reads as precondition
    - E-P9-02: quorum achievable by one flash-loan actor within one block
    - E-P9-03: governance can unpause a contract paused during an active exploit
""",
    "solana": """
SOLANA ACCESS CONTROL — FRANK CASTLE 6-STEP VALIDATION:
Apply to EVERY account in EVERY instruction. A finding is required if ANY step is missing.

  STEP 1 KEY:            account.key == expected (stored address or PDA derivation)
  STEP 2 OWNER:          account.owner == expected_program_id  ← Cashio $48M — missing
  STEP 3 SIGNER:         account.is_signer == true for authorities ← Wormhole $320M — missing
  STEP 4 WRITABLE:       account.is_writable before any mutation
  STEP 5 DISCRIMINATOR:  data[..8] == ExpectedType::DISCRIMINATOR
  STEP 6 DATA:           semantic invariants (is_initialized, version, authority)

IMPORTANT: has_one in Anchor checks KEY (step 1) but NOT SIGNER (step 3).
  A function with only has_one = authority is still missing a signer check.

ADDITIONAL PATTERNS:
  - S-P2-01: token_program.key not validated against spl_token::id() before invoke()
  - S-P3-01: user-supplied bump used instead of stored canonical bump → shadow PDA
  - S-P5-04: init_if_needed without explicit is_initialized guard → reinitialization
  - S-P3-04: two authority domains can derive the same PDA address via overlapping seeds
  - S-A0-08: same account passed twice as &mut → double mutation race
  - S-P0-07: UncheckedAccount without /// CHECK: comment AND manual 6-step validation
""",
    "sui": """
SUI MOVE ACCESS CONTROL PATTERNS:
  - S-A0-01 + S-A0-07: ctx.sender() behind shared object resolves to the EXTERNAL CALLER,
    not the object holding the capability. Store owner at wrap time; never derive at access time.
  - S-P0-07: public(package) + entry combination makes a function world-callable.
    The entry modifier overrides package visibility.
  - S-P1-09: privilege check uses an address PARAMETER instead of assert_eq!(addr, ctx.sender())
  - S-P1-10: Cap<phantom R> without R constrained to specific types → UserRole passes for AdminRole
  - S-P2-09: two different-type key objects destructured and reconstructed with swapped UIDs
  - S-A0-08: protocol invariants rely on creating module controlling transfer of a key+store object.
    Any holder can call public_transfer() or public_freeze() without the module's involvement.
  - S-A0-09: OTW struct has extra fields beyond one dummy bool → uniqueness guarantee broken
""",
    "bitcoin": """
BITCOIN ACCESS CONTROL PATTERNS:
  - B-A0-01 + B-P2-01: CreateBTCDelegation / stake_entry accepts a coinbase transaction
    (prevout.hash == 0x00..00, index == 0xFFFFFFFF). Slashing requires spending the
    staking UTXO; coinbase outputs are locked for 100 blocks. If min_staking_time < 100,
    the attacker can double-sign then unstake before slashing executes. CRIT if present.
  - B-A0-04: min_staking_time < 100 blocks without explicit coinbase rejection at entry
  - B-P5-01: for any (staking_start, misbehavior_block, unbonding_time), is there
    always time for slash_tx to confirm before unbonding_tx completes?
  - B-A0-05 + B-P4-02: slashing TX built for P2WPKH but staking output is P2TR → invalid slash
  - B-P6-01: bridge accepts coinbase deposit with fewer than 100 confirmations
""",
}


# ── Nano implementation ───────────────────────────────────────────────────────

class AccessControlSpecialistNano(BaseSpecialistNano):

    NANO_NAME = "AccessControlSpecialist"
    VULNERABILITY_CLASSES = [
        "access-control",
        "missing-check",
        "privilege-escalation",
        "initializer",
        "upgrade-security",
        "governance",
        "bitcoin-coinbase",
        "solana-six-step",
        "sui-capability",
    ]
    SUPPORTED_CHAINS = ["ethereum", "solana", "sui", "bitcoin"]

    def _build_system_prompt(self, chain: str) -> str:
        return _BASE_SYSTEM + _CHAIN_ADDENDUM.get(chain, "")

    def _parse_response(self, raw_text: str, result: NanoResult, chain: str) -> NanoResult:
        if "```" in raw_text:
            result.reasoning_trace = raw_text.split("```")[0].strip()[:400]

        raw_findings = self._extract_json(raw_text)

        for i, raw in enumerate(raw_findings):
            if not isinstance(raw, dict) or not raw.get("title"):
                continue

            raw.setdefault("finding_id", f"AC-{i+1:03d}")

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

            # Solana: downgrade if 6-step evidence doesn't specify a missing step
            if chain == "solana":
                six_step = raw.get("evidence", {}).get("six_step_result", {})
                has_missing = any(v == "missing" for v in six_step.values())
                if not has_missing and raw.get("class") == "missing_check":
                    confidence = min(confidence, 0.60)

            finding = Finding(
                nano=self.NANO_NAME,
                finding_id=raw["finding_id"],
                title=raw.get("title", ""),
                vuln_class=raw.get("class", "missing_check"),
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
