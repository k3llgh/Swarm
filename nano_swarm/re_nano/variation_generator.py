"""
nano_swarm/re_nano/variation_generator.py
──────────────────────────────────────────
Phase 2 of the RE Nano pipeline.

Generates diverse code examples from an AbstractPattern.
Each example differs from all existing curriculum items on a cosine-distance
metric: if the embedding of the new code is within DIVERSITY_THRESHOLD of any
existing item, the example is rejected and the generator is steered toward
under-represented structural dimensions.

Label distribution per batch:
  50% vulnerable   — bug clearly present and exploitable
  30% protected    — correctly mitigated; serves as negative example
  20% adversarial  — looks vulnerable; a subtle guard prevents exploitation
                     (highest-value label for reducing false positives)
"""
from __future__ import annotations

import json
import logging
import math
import random
import re
from typing import Optional

from ..llm_client import get_client
from .schemas import (
    AbstractPattern, Chain, CodeVariation, Label, StructuralDimensions
)

log = logging.getLogger(__name__)

# ── Structural dimensions ─────────────────────────────────────────────────────
# Every generated example is characterised along these axes.
# The dimension tracker enforces coverage: if "2-hop" nesting_depth has never
# appeared, the next generation request will force that value.

DIMENSIONS: dict[str, list[str]] = {
    "function_name": [
        "withdraw", "claim", "redeem", "harvest", "liquidate",
        "borrow", "stake", "unstake", "swap", "settle", "bridge_deposit",
    ],
    "protocol_type": [
        "lending", "AMM", "staking", "bridge", "vault", "governance", "NFT-marketplace",
    ],
    "guard_presence": [
        "none",                # no guard — clearly vulnerable
        "wrong_frame",         # guard on function A; bug in function B sharing state
        "correct",             # correctly guarded — protected example
        "inherited_missing",   # guard in base contract; child overrides without it
    ],
    "external_call_target": [
        "ERC20_transfer", "ETH_transfer", "arbitrary_callback",
        "CPI_token_program", "oracle_call", "library_delegatecall",
    ],
    "vuln_variant": [
        "standard", "cross-function", "read-only", "cross-contract", "2-hop",
    ],
    "nesting_depth": [
        "direct", "1-hop", "2-hop", "library-dispatch",
    ],
    "language_pattern": [
        "vanilla", "fork-compound", "fork-aave", "with-library", "inline-assembly",
    ],
}

LABEL_WEIGHTS: dict[str, float] = {
    "vulnerable":  0.50,
    "protected":   0.30,
    "adversarial": 0.20,
}

# Reject generated example if within this cosine distance of any existing item
DIVERSITY_THRESHOLD = 0.25


# ── Prompt template ───────────────────────────────────────────────────────────

_SYSTEM = """\
You generate training data for a blockchain security auditing AI.

You will receive a vulnerability pattern and constraints.
Produce ONE realistic code example that exactly matches the constraints.

Output a JSON object — no markdown, no preamble:
{
  "label":            "vulnerable" | "protected" | "adversarial",
  "code":             "<complete source code as a single string>",
  "poc":              "<exploit proof-of-concept code, or null if label is protected>",
  "teaching_summary": "<one sentence: what makes this example interesting>"
}

Quality rules:
  - Realistic naming — not 'evil_function' or 'vuln_var'
  - Label 'vulnerable':   the bug must be clearly present and exploitable
  - Label 'protected':    include a correct guard; the bug class is absent
  - Label 'adversarial':  the code LOOKS like label=vulnerable at first glance,
                          but a subtle guard (inherited modifier, intermediate check,
                          or architectural pattern) actually prevents exploitation
  - The PoC must be runnable: Foundry test for Solidity, Anchor test for Rust, Move test
"""


# ── Dimension tracker ─────────────────────────────────────────────────────────

class DimensionTracker:
    """Tracks how often each dimension value has appeared in the curriculum."""

    def __init__(self) -> None:
        self.counts: dict[str, dict[str, int]] = {
            dim: {val: 0 for val in vals}
            for dim, vals in DIMENSIONS.items()
        }

    def update(self, dims: StructuralDimensions) -> None:
        for dim_name, value in dims.model_dump().items():
            if dim_name in self.counts and value in self.counts[dim_name]:
                self.counts[dim_name][value] += 1

    def most_underrepresented(self) -> tuple[str, str]:
        """Return (dimension_name, value) with the lowest appearance count."""
        best_dim, best_val, best_count = "function_name", "withdraw", float("inf")
        for dim_name, val_counts in self.counts.items():
            for val, count in val_counts.items():
                if count < best_count:
                    best_count, best_dim, best_val = count, dim_name, val
        return best_dim, best_val

    def report(self) -> str:
        lines: list[str] = []
        for dim, vals in self.counts.items():
            total = sum(vals.values())
            lines.append(f"  {dim}: {dict(vals)} (total={total})")
        return "\n".join(lines)


# ── Lightweight embedding ─────────────────────────────────────────────────────
# TF-IDF over identifier tokens. No GPU required.
# Swap for a code embedding model (e.g. CodeBERT) in production
# by replacing _embed() and cosine_distance() below.

_VOCAB: dict[str, int] = {}


def _embed(code: str, dim: int = 512) -> list[float]:
    tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", code.lower())
    for t in tokens:
        if t not in _VOCAB:
            _VOCAB[t] = len(_VOCAB)

    tf: dict[str, float] = {}
    for t in tokens:
        tf[t] = tf.get(t, 0) + 1
    n = max(len(tokens), 1)
    tf = {k: v / n for k, v in tf.items()}

    vec_len = min(len(_VOCAB), dim)
    vec = [0.0] * vec_len
    for token, freq in tf.items():
        idx = _VOCAB.get(token)
        if idx is not None and idx < vec_len:
            vec[idx] = freq

    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


def cosine_distance(a: list[float], b: list[float]) -> float:
    """1 − cosine_similarity. Range [0, 2]. Lower means more similar."""
    return 1.0 - sum(x * y for x, y in zip(a, b))


# ── Main generator ────────────────────────────────────────────────────────────

def generate_variations(
    pattern: AbstractPattern,
    target_size: int = 30,
    max_attempts: int = 150,
    diversity_threshold: float = DIVERSITY_THRESHOLD,
) -> tuple[list[CodeVariation], DimensionTracker]:
    """
    Generate `target_size` diverse code variations for one AbstractPattern.

    The generator steers itself toward under-represented structural dimensions
    when diversity misses accumulate, and reports each miss for Loop 3 logging.

    Returns:
        (approved_variations, dimension_tracker) tuple.
    """
    curriculum: list[CodeVariation] = []
    tracker = DimensionTracker()
    client = get_client()

    chain_lang = {
        Chain.ETHEREUM: "Solidity (^0.8.0)",
        Chain.SOLANA:   "Rust with Anchor framework",
        Chain.SUI:      "Sui Move",
        Chain.BITCOIN:  "Python pseudocode (not executable)",
    }.get(pattern.chain, "Solidity (^0.8.0)")

    consecutive_misses = 0
    attempts = 0

    log.info("Generating %d variations for %s…", target_size, pattern.pattern_id)

    while len(curriculum) < target_size and attempts < max_attempts:
        attempts += 1

        # Choose label by configured distribution
        label = random.choices(
            list(LABEL_WEIGHTS.keys()),
            weights=list(LABEL_WEIGHTS.values()),
        )[0]

        # After several consecutive diversity misses, force the most
        # under-represented dimension to break the cluster
        force_dim: Optional[tuple[str, str]] = None
        if consecutive_misses >= 3:
            force_dim = tracker.most_underrepresented()

        try:
            raw = _call_api(client, pattern, label, force_dim, chain_lang)
        except Exception as exc:
            log.debug("Generation API error (attempt %d): %s", attempts, exc)
            continue

        code = raw.get("code", "")
        if not code or len(code) < 60:
            continue

        embedding = _embed(code)

        # Diversity check
        if _too_similar(embedding, curriculum, diversity_threshold):
            consecutive_misses += 1
            log.debug("Diversity miss (attempt %d, %d consecutive)", attempts, consecutive_misses)
            yield_diversity_miss(pattern.pattern_id, label, consecutive_misses)
            continue

        consecutive_misses = 0
        dims = _infer_dims(code, label, force_dim)
        tracker.update(dims)

        variation = CodeVariation(
            variation_id=f"{pattern.pattern_id}-v{len(curriculum)+1:03d}",
            pattern_id=pattern.pattern_id,
            chain=pattern.chain,
            vuln_class=pattern.vulnerability_class,
            checklist_refs=pattern.checklist_refs,
            label=Label(label),
            code=code,
            poc=raw.get("poc"),
            dims=dims,
            embedding=embedding,
        )
        curriculum.append(variation)

        icon = {"vulnerable": "✗", "protected": "✓", "adversarial": "⚠"}.get(label, "?")
        log.info("  %s [%02d/%d] %s — %s/%s",
                 icon, len(curriculum), target_size, label,
                 dims.function_name, dims.protocol_type)

    log.info("Done: %d variations in %d attempts. Dimension coverage:\n%s",
             len(curriculum), attempts, tracker.report())

    return curriculum, tracker


def yield_diversity_miss(pattern_id: str, label: str, consecutive: int) -> None:
    """
    Hook for Loop 3: called each time a generated example is rejected for
    being too similar to existing curriculum. The RE Nano's self-education
    module picks up these signals from the pitfall log.
    """
    # Imported here to avoid circular imports
    from .self_education import log_diversity_miss
    log_diversity_miss(pattern_id=pattern_id, label=label, consecutive=consecutive)


# ── Private helpers ───────────────────────────────────────────────────────────

def _call_api(
    client,
    pattern: AbstractPattern,
    label: str,
    force_dim: Optional[tuple[str, str]],
    chain_lang: str,
) -> dict:
    dim_constraint = ""
    if force_dim:
        dim_name, dim_val = force_dim
        dim_constraint = (
            f"\nREQUIRED: the code MUST use '{dim_val}' as the {dim_name}. "
            "Do not deviate from this constraint.\n"
        )

    user = (
        f"Vulnerability pattern: {pattern.vulnerability_class}\n"
        f"Chain / language: {pattern.chain.value} / {chain_lang}\n"
        f"Label to generate: {label}\n"
        f"{dim_constraint}\n"
        f"Pattern details:\n"
        f"  Invariant violated:  {pattern.invariant_violated}\n"
        f"  Required elements:   {json.dumps(pattern.required_elements)}\n"
        f"  Attacker action:     {pattern.attacker_action}\n"
        f"  Exploit primitive:   {pattern.exploit_primitive}\n"
        f"  Known variants:      {json.dumps(pattern.known_variants)}\n"
        f"  False-positive traps: {json.dumps(pattern.false_positive_traps)}\n\n"
        "Generate the code example now."
    )

    response = client.chat(system=_SYSTEM, user=user, max_tokens=3000, temperature=0.7)
    return response.as_json()


def _too_similar(
    embedding: list[float],
    curriculum: list[CodeVariation],
    threshold: float,
) -> bool:
    return any(
        cosine_distance(embedding, item.embedding) < threshold
        for item in curriculum
        if item.embedding
    )


def _infer_dims(
    code: str,
    label: str,
    force_dim: Optional[tuple[str, str]],
) -> StructuralDimensions:
    """Heuristic extraction of structural dimensions from generated code."""
    lower = code.lower()

    fn = next(
        (f for f in DIMENSIONS["function_name"] if f"fn {f}" in lower or f"function {f}" in lower),
        "withdraw",
    )
    protocol = next(
        (p for p in DIMENSIONS["protocol_type"] if p.replace("-", " ") in lower),
        "lending",
    )
    guard = "correct" if label == "protected" else "none"
    if any(g in lower for g in ("nonreentrant", "non_reentrant", "reentrancyguard")):
        guard = "correct" if label == "protected" else "wrong_frame"
    ext_call = "CPI_token_program" if "invoke" in lower or "cpi" in lower else "ERC20_transfer"

    dims = {
        "function_name":        fn,
        "protocol_type":        protocol,
        "guard_presence":       guard,
        "external_call_target": ext_call,
        "vuln_variant":         "standard",
        "nesting_depth":        "direct",
        "language_pattern":     "vanilla",
    }

    if force_dim:
        dims[force_dim[0]] = force_dim[1]

    return StructuralDimensions(**dims)
