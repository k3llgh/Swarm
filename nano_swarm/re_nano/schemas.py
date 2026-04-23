"""
nano_swarm/re_nano/schemas.py
──────────────────────────────
Data contracts for the RE & Teaching Nano pipeline.

All inter-component communication uses these types.
Lock these schemas before training anything — changing them
after curriculum generation breaks deserialization.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enumerations ──────────────────────────────────────────────────────────────

class Chain(str, Enum):
    ETHEREUM = "ethereum"
    SOLANA   = "solana"
    SUI      = "sui"
    BITCOIN  = "bitcoin"
    MULTI    = "multi"          # multi-chain exploits; resolved to primary chain


class Severity(str, Enum):
    CRIT = "CRIT"
    HIGH = "HIGH"
    MED  = "MED"
    LOW  = "LOW"


class Stealth(str, Enum):
    HIGH = "HIGH"
    MED  = "MED"
    LOW  = "LOW"


class Label(str, Enum):
    """Ground-truth label for a generated code example."""
    VULNERABLE          = "vulnerable"     # bug is present and exploitable
    PROTECTED           = "protected"      # correctly mitigated
    ADVERSARIAL         = "adversarial"    # looks vulnerable; guard prevents exploit


class CurriculumLabel(str, Enum):
    """Outcome label after sandbox validation."""
    CONFIRMED_VULNERABLE = "CONFIRMED_VULNERABLE"   # PoC passed sandbox
    CONFIRMED_PROTECTED  = "CONFIRMED_PROTECTED"    # three PoC attempts all failed
    NEEDS_HUMAN_REVIEW   = "NEEDS_HUMAN_REVIEW"     # sandbox limitation; held for human
    DESCRIPTION_ONLY     = "DESCRIPTION_ONLY"       # Bitcoin — no sandbox available


class FaultType(str, Enum):
    """Why a sandbox PoC attempt failed."""
    BAD_POC             = "bad_poc"             # vulnerability exists; exploit code wrong
    WRONG_SEQUENCE      = "wrong_sequence"      # attack entry point or order incorrect
    SANDBOX_LIMITATION  = "sandbox_limitation"  # condition not modelable locally
    TRULY_ABSENT        = "truly_absent"        # vulnerability is genuinely not present


# ── Seed material ─────────────────────────────────────────────────────────────

class ExploitSeed(BaseModel):
    """A single real-world exploit post-mortem, as loaded from exploit_seeds.json."""

    title:               str
    chain:               str
    vulnerability_class: str
    root_cause:          str
    loss_amount_usd:     Optional[int]
    affected_protocol:   str
    exploit_transaction: Optional[str]
    post_mortem_link:    Optional[str]
    checklist_ids:       list[str]
    severity:            str
    stealth:             str
    notes:               str = ""


# ── Phase 1: abstract pattern ─────────────────────────────────────────────────

class AbstractPattern(BaseModel):
    """
    Generalised description of a vulnerability class extracted from N seeds.
    Chain- and protocol-agnostic: describes the invariant, not the instance.
    """

    pattern_id:          str              # e.g. "ETH-REENTRANCY-003"
    vulnerability_class: str              # canonical name from seed grouping
    chain:               Chain
    checklist_refs:      list[str]        # deduplicated from all seeds in group
    severity:            Severity
    stealth:             Stealth

    # Core adversarial description (extracted by the LLM)
    required_elements:      list[str]     # what must be present for the bug to exist
    invariant_violated:     str           # the security property that breaks
    attacker_action:        str           # what the attacker does
    exploit_primitive:      str           # mechanism: callback / CPI / PTB command…
    known_variants:         list[str]     # distinct surface-level manifestations
    false_positive_traps:   list[str]     # patterns that LOOK vulnerable but are not
    detection_hints:        list[str]     # code patterns worth grepping for
    fix_pattern:            str           # canonical remediation (one sentence)

    # Metadata
    seed_exploits:       list[str]        # source exploit titles
    total_loss_usd:      Optional[int]

    # Sandbox configuration
    sandboxable:         bool = True      # False for Bitcoin (regtest not modelled)
    sandbox_fidelity:    float = 1.0      # chain confidence modifier (0.7–1.0)


# ── Phase 2: code variation ───────────────────────────────────────────────────

class StructuralDimensions(BaseModel):
    """
    Axes of variation for a generated code example.
    Used to enforce diversity: each new example must differ on ≥2 axes.
    """
    function_name:        str    # e.g. withdraw / stake / liquidate
    protocol_type:        str    # lending / AMM / staking / bridge / vault
    guard_presence:       str    # none / wrong_frame / correct / inherited_missing
    external_call_target: str    # ERC20 / ETH / arbitrary_callback / CPI / oracle
    vuln_variant:         str    # standard / cross-function / read-only / 2-hop
    nesting_depth:        str    # direct / 1-hop / 2-hop / library-dispatch
    language_pattern:     str    # vanilla / fork-compound / with-library / assembly


class CodeVariation(BaseModel):
    """A single generated code example, pre-sandbox-validation."""

    variation_id:    str              # e.g. "ETH-REENTRANCY-003-v047"
    pattern_id:      str
    chain:           Chain
    vuln_class:      str
    checklist_refs:  list[str]
    label:           Label            # what the generator intended
    code:            str              # the generated source
    poc:             Optional[str]    # generated exploit proof-of-concept
    dims:            StructuralDimensions
    embedding:       Optional[list[float]] = None   # populated after generation


# ── Phase 3: sandbox results ──────────────────────────────────────────────────

class SandboxAttempt(BaseModel):
    """Outcome of one PoC execution attempt."""

    attempt_number: int
    poc_code:       str
    succeeded:      bool
    funds_moved:    Optional[str]     # description of on-chain state change
    revert_reason:  Optional[str]
    error_output:   Optional[str]
    fault:          Optional[FaultType]
    fault_detail:   Optional[str]


class SandboxResult(BaseModel):
    """Aggregate result across all PoC attempts for one code variation."""

    variation_id:    str
    attempts:        list[SandboxAttempt]
    final_label:     CurriculumLabel
    training_weight: float            # raw weight before chain fidelity modifier
    confirmed_at:    Optional[int]    # attempt number on which PoC succeeded
    notes:           str = ""


# ── Phase 4: curriculum item ──────────────────────────────────────────────────

class CurriculumItem(BaseModel):
    """
    A fully-validated training example ready to teach specialist nanos.
    Stored in data/curriculum/{pattern_id}.json.
    """

    curriculum_id:       str
    pattern_id:          str
    chain:               Chain
    vuln_class:          str
    checklist_refs:      list[str]
    severity:            Severity
    stealth:             Stealth

    # Ground truth
    label:               CurriculumLabel
    training_weight:     float         # sandbox_weight × chain_fidelity

    # Content
    code:                str
    poc:                 Optional[str]
    dims:                StructuralDimensions
    embedding:           list[float]
    teaching_summary:    str           # one-sentence description for few-shot context

    # Provenance
    sandbox_confirmed:   bool
    attempts_required:   Optional[int]
    source_seeds:        list[str]     # exploit titles this example descends from
    created_at:          str           # ISO-8601 timestamp


# ── Phase 5: teaching context ─────────────────────────────────────────────────

class TeachingContext(BaseModel):
    """
    Few-shot examples injected into a specialist nano's prompt.
    Built by curriculum.py from the curriculum store.
    """

    nano_target:         str           # "ReentrancyMaster" | "AccessControlSpecialist"
    zone_id:             str
    chain:               Chain
    vuln_class:          str
    few_shot_messages:   list[dict]    # list of {role, content} dicts
    curriculum_ids_used: list[str]
    example_count:       int
    has_adversarial:     bool          # true if any adversarial examples included


# ── Loop 3: RE Nano pitfall log ───────────────────────────────────────────────

class PitfallEntry(BaseModel):
    """
    A mistake the RE Nano made, logged for in-context self-correction.
    Stored in data/pitfall_logs/{pattern_id}.jsonl (one JSON per line).
    """

    pattern_id:      str
    variation_id:    str
    pitfall_type:    str    # bad_poc / wrong_sequence / diversity_miss / sandbox_limitation
    description:     str    # what went wrong
    fix_applied:     str    # what RE Nano did to correct it
    attempts_wasted: int
    resolved:        bool   # True once the same mistake stops recurring
    timestamp:       str    # ISO-8601
