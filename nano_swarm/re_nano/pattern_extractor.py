"""
nano_swarm/re_nano/pattern_extractor.py
────────────────────────────────────────
Phase 1 of the RE Nano pipeline.

Takes a group of exploit seeds sharing the same vulnerability class and
asks the LLM (DeepSeek V3 by default) to generalise them into a single
AbstractPattern — protocol-agnostic, adversarially framed.

The model is given a structured prompt and must return strict JSON.
If the JSON parse fails the call is retried up to max_retries times.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

from ..llm_client import get_client
from .schemas import AbstractPattern, Chain, ExploitSeed, Severity, Stealth
from .seed_ingestion import CHAIN_FIDELITY, build_pattern_id

log = logging.getLogger(__name__)

# ── Prompt templates ──────────────────────────────────────────────────────────

_SYSTEM = """\
You are the Reverse Engineering component of a self-educating blockchain security system.

Task: given a group of real-world exploits that share the same vulnerability class,
extract the GENERALISED ABSTRACT PATTERN — independent of any specific protocol,
token, or implementation detail.

Rules:
- Frame everything from the attacker's perspective
- Every "required element" must be something checkable in code, not a vague principle
- List every known surface-level variant, including obfuscated or indirect forms
- The false-positive traps section is critical: patterns that LOOK vulnerable but are NOT
- Detection hints are grep-friendly code patterns (function signatures, keywords, modifiers)

Output format: a single JSON object — no markdown fences, no preamble, just the JSON.

Schema:
{
  "required_elements":    ["what must be present in code for this vulnerability to exist"],
  "invariant_violated":   "the security property that breaks (one sentence)",
  "attacker_action":      "what the attacker does to exploit this (one sentence)",
  "exploit_primitive":    "the mechanism: ERC20 callback / CPI / PTB command / …",
  "known_variants":       ["distinct surface-level manifestations of this pattern"],
  "false_positive_traps": ["patterns that look vulnerable but are NOT exploitable"],
  "detection_hints":      ["code pattern to grep for when scanning"],
  "fix_pattern":          "canonical remediation (one sentence)"
}
"""


def _build_prompt(
    chain: str,
    vuln_class: str,
    seeds: list[ExploitSeed],
) -> str:
    """Build the user-turn content for pattern extraction."""
    total_loss = sum(s.loss_amount_usd for s in seeds if s.loss_amount_usd)

    lines: list[str] = [
        f"Chain: {chain}",
        f"Vulnerability class: {vuln_class}",
        f"Exploit group size: {len(seeds)} seeds",
        f"Total confirmed losses: ${total_loss:,}" if total_loss else "Total confirmed losses: not quantified",
        "",
        "Exploits in this group:",
        "",
    ]

    for i, seed in enumerate(seeds, 1):
        loss_str = f"${seed.loss_amount_usd:,}" if seed.loss_amount_usd else "not quantified"
        lines.append(f"{i}. {seed.title} ({seed.affected_protocol})")
        lines.append(f"   Loss: {loss_str}")
        lines.append(f"   Root cause: {seed.root_cause}")
        if seed.notes:
            lines.append(f"   Notes: {seed.notes}")
        lines.append("")

    lines.append("Extract the generalised abstract pattern from these exploits.")
    return "\n".join(lines)


# ── Public interface ──────────────────────────────────────────────────────────

def extract_pattern(
    chain: str,
    vuln_class: str,
    seeds: list[ExploitSeed],
    seq: int,
    max_retries: int = 3,
) -> AbstractPattern:
    """
    Call the LLM to extract an AbstractPattern from a seed group.

    Args:
        chain:       canonical chain name ("ethereum", "solana", etc.)
        vuln_class:  canonical vulnerability class name
        seeds:       all seeds in this pattern bucket
        seq:         sequential number for the pattern ID
        max_retries: number of JSON-parse retries on malformed output

    Returns:
        A validated AbstractPattern instance.

    Raises:
        RuntimeError if the LLM returns non-parseable output after all retries.
    """
    pattern_id = build_pattern_id(chain, vuln_class, seq)
    client = get_client()
    prompt = _build_prompt(chain, vuln_class, seeds)

    raw: dict = {}
    last_error: Optional[Exception] = None

    for attempt in range(1, max_retries + 1):
        try:
            response = client.chat(
                system=_SYSTEM,
                user=prompt,
                max_tokens=2000,
                temperature=0.1,    # low temperature for structured extraction
            )
            raw = response.as_json()
            break
        except ValueError as exc:
            last_error = exc
            log.warning("Pattern extraction parse failure (attempt %d/%d): %s", attempt, max_retries, exc)
            if attempt < max_retries:
                time.sleep(1)
        except Exception as exc:
            last_error = exc
            log.warning("Pattern extraction API failure (attempt %d/%d): %s", attempt, max_retries, exc)
            if attempt < max_retries:
                time.sleep(2 ** attempt)

    if not raw:
        raise RuntimeError(
            f"Pattern extraction failed for {pattern_id} after {max_retries} attempts. "
            f"Last error: {last_error}"
        )

    # Resolve metadata from the seed group
    effective_chain = chain if chain != "multi" else "ethereum"
    fidelity = CHAIN_FIDELITY.get(effective_chain, 0.8)
    sandboxable = effective_chain != "bitcoin"

    sev_rank = {"CRIT": 3, "HIGH": 2, "MED": 1, "LOW": 0}
    top_seed = max(seeds, key=lambda s: sev_rank.get(s.severity, 0))

    return AbstractPattern(
        pattern_id=pattern_id,
        vulnerability_class=vuln_class,
        chain=Chain(effective_chain) if effective_chain in Chain.__members__.values() else Chain.ETHEREUM,
        checklist_refs=_dedup_refs(seeds),
        severity=Severity(top_seed.severity),
        stealth=Stealth(top_seed.stealth),
        required_elements=raw.get("required_elements", []),
        invariant_violated=raw.get("invariant_violated", ""),
        attacker_action=raw.get("attacker_action", ""),
        exploit_primitive=raw.get("exploit_primitive", ""),
        known_variants=raw.get("known_variants", []),
        false_positive_traps=raw.get("false_positive_traps", []),
        detection_hints=raw.get("detection_hints", []),
        fix_pattern=raw.get("fix_pattern", ""),
        seed_exploits=[s.title for s in seeds],
        total_loss_usd=sum(s.loss_amount_usd for s in seeds if s.loss_amount_usd) or None,
        sandboxable=sandboxable,
        sandbox_fidelity=fidelity,
    )


def extract_all_patterns(
    seeds_path: Path,
    output_path: Optional[Path] = None,
    max_patterns: Optional[int] = None,
) -> list[AbstractPattern]:
    """
    Convenience wrapper: load seeds, extract all patterns, optionally cache to disk.

    Args:
        seeds_path:   path to exploit_seeds.json
        output_path:  if provided, write JSON array of patterns here
        max_patterns: stop after this many patterns (useful for pilots)

    Returns:
        List of AbstractPattern instances.
    """
    from .seed_ingestion import load_seeds, iter_groups

    seeds = load_seeds(seeds_path)
    patterns: list[AbstractPattern] = []

    for seq, (chain, vuln_class, group) in enumerate(iter_groups(seeds), 1):
        if max_patterns and seq > max_patterns:
            break

        loss = sum(s.loss_amount_usd for s in group if s.loss_amount_usd)
        log.info("[%03d] Extracting: [%s] %s (%d seeds, $%s)", seq, chain, vuln_class, len(group),
                 f"{loss:,}" if loss else "?")

        try:
            pattern = extract_pattern(chain, vuln_class, group, seq)
            patterns.append(pattern)
            log.info("      ✓ %s — %d variants, sandboxable=%s",
                     pattern.pattern_id, len(pattern.known_variants), pattern.sandboxable)
        except Exception as exc:
            log.error("      ✗ FAILED: %s", exc)

        time.sleep(0.3)  # gentle rate limiting

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as fh:
            json.dump([p.model_dump() for p in patterns], fh, indent=2, default=str)
        log.info("Saved %d patterns → %s", len(patterns), output_path)

    return patterns


# ── Private helpers ───────────────────────────────────────────────────────────

def _dedup_refs(seeds: list[ExploitSeed]) -> list[str]:
    """Return deduplicated checklist IDs from all seeds, preserving first-seen order."""
    seen: set[str] = set()
    refs: list[str] = []
    for seed in seeds:
        for ref in seed.checklist_ids:
            if ref not in seen:
                seen.add(ref)
                refs.append(ref)
    return refs
