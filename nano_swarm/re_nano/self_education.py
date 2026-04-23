"""
nano_swarm/re_nano/self_education.py
──────────────────────────────────────
Loop 3 — RE Nano self-education from its own sandbox failures.

Every time a PoC fails or a generated example is rejected for being
too similar to existing curriculum, a PitfallEntry is appended to the
pattern's JSONL log in data/pitfall_logs/.

At generation time, the RE Nano reads its own pitfall log and prepends
it to its generation prompt so it avoids repeating known mistakes.

This loop has NO LoRA update in Phase 1 — it operates entirely through
in-context self-correction. When the pitfall log exceeds 500 entries,
a LoRA fine-tune of the variation generator is recommended.

Tracked metric (Loop 3 health):
  attempts_required_per_pattern — should decrease over 90 days as the
  RE Nano internalises what works for each vulnerability class.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..config import settings
from .schemas import CodeVariation, FaultType, PitfallEntry

log = logging.getLogger(__name__)

# Recommend LoRA fine-tune of the RE Nano generator when the pitfall log
# for any single pattern exceeds this many entries.
LORA_TRANSITION_THRESHOLD = 500


# ── Logging ───────────────────────────────────────────────────────────────────

def log_sandbox_failure(
    pattern_id: str,
    variation: CodeVariation,
    fault_type: FaultType,
    explanation: str,
    fix_applied: str,
    attempts_wasted: int,
    resolved: bool,
) -> None:
    """
    Append a sandbox failure to the pattern's pitfall log.
    Called by the sandbox validator after each failed PoC attempt.
    """
    entry = PitfallEntry(
        pattern_id=pattern_id,
        variation_id=variation.variation_id,
        pitfall_type=fault_type.value,
        description=explanation,
        fix_applied=fix_applied,
        attempts_wasted=attempts_wasted,
        resolved=resolved,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    _append(entry)


def log_diversity_miss(pattern_id: str, label: str, consecutive: int) -> None:
    """
    Append a diversity miss to the pitfall log.
    Called by the variation generator when a generated example is rejected
    for being too similar to an existing curriculum item.
    """
    entry = PitfallEntry(
        pattern_id=pattern_id,
        variation_id=f"miss-{consecutive}",
        pitfall_type="diversity_miss",
        description=(
            f"Generated {label!r} example was within diversity threshold "
            f"({consecutive} consecutive misses)"
        ),
        fix_applied="Steer generation toward most under-represented structural dimension",
        attempts_wasted=1,
        resolved=False,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    _append(entry)


def log_loop1_rejection(
    pattern_id: str,
    chain: str,
    vuln_class: str,
    invalidation_code: str,
    explanation: str,
) -> None:
    """
    Append a Loop 1 signal: a triage rejection of a specialist nano finding.
    The RE Nano will generate adversarial examples targeting this mistake class.
    """
    entry = PitfallEntry(
        pattern_id=pattern_id,
        variation_id="loop1-signal",
        pitfall_type="triage_rejection",
        description=f"[{invalidation_code}] {explanation}",
        fix_applied=(
            "Generate adversarial examples: 5 truly-vulnerable (guard absent) + "
            "5 adversarial (subtle guard present that specialist missed)"
        ),
        attempts_wasted=0,
        resolved=False,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    _append(entry)


def log_loop2_overturn(
    pattern_id: str,
    triage_decision: str,
    jury_verdict: str,
    triage_step: str,
    reason_applied: str,
    correction: str,
) -> None:
    """
    Append a Loop 2 signal: a jury overturn of a triage decision.
    The triage nano training curriculum will be updated with this correction.
    """
    entry = PitfallEntry(
        pattern_id=pattern_id,
        variation_id="loop2-signal",
        pitfall_type="jury_overturn",
        description=(
            f"Triage said {triage_decision}, jury said {jury_verdict}. "
            f"Triage applied {reason_applied} at step {triage_step} incorrectly."
        ),
        fix_applied=correction,
        attempts_wasted=0,
        resolved=True,   # jury overturns are confirmed corrections
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    _append(entry)


# ── In-context self-correction ────────────────────────────────────────────────

def build_pitfall_context(pattern_id: str, max_entries: int = 20) -> str:
    """
    Build the pitfall context string to prepend to the RE Nano's generation prompt.
    Shows the most recent resolved pitfalls so the model avoids known mistakes.
    Returns an empty string if the log is empty.
    """
    entries = _load(pattern_id)
    if not entries:
        return ""

    # Prioritise resolved entries (lessons already confirmed to be correct)
    resolved = [e for e in entries if e.get("resolved", False)]
    recent = (resolved or entries)[-max_entries:]

    by_type: dict[str, list[dict]] = {}
    for e in recent:
        by_type.setdefault(e["pitfall_type"], []).append(e)

    lines = [f"PITFALL LOG for {pattern_id} — avoid these known mistakes:", ""]
    for ptype, group in by_type.items():
        lines.append(f"[{ptype.upper()}] — {len(group)} occurrences:")
        for entry in group[-3:]:
            lines.append(f"  Mistake: {entry['description']}")
            lines.append(f"  Fix:     {entry['fix_applied']}")
        lines.append("")

    return "\n".join(lines)


# ── Statistics ────────────────────────────────────────────────────────────────

def pitfall_stats() -> dict:
    """Return aggregate statistics across all pattern pitfall logs."""
    settings.pitfall_dir.mkdir(parents=True, exist_ok=True)
    all_entries: list[dict] = []

    for path in settings.pitfall_dir.glob("*.jsonl"):
        with open(path) as fh:
            for line in fh:
                if line.strip():
                    all_entries.append(json.loads(line))

    resolved = sum(1 for e in all_entries if e.get("resolved"))
    by_type: dict[str, int] = {}
    for e in all_entries:
        by_type[e["pitfall_type"]] = by_type.get(e["pitfall_type"], 0) + 1

    return {
        "total_entries":                 len(all_entries),
        "resolved_rate":                 resolved / max(len(all_entries), 1),
        "by_type":                       by_type,
        "lora_transition_recommended":   len(all_entries) > LORA_TRANSITION_THRESHOLD,
    }


def attempts_trend() -> dict[str, float]:
    """
    Loop 3 health metric: average attempts_wasted per pattern.
    A decreasing trend means the RE Nano is learning.
    """
    settings.pitfall_dir.mkdir(parents=True, exist_ok=True)
    totals: dict[str, list[int]] = {}

    for path in settings.pitfall_dir.glob("*.jsonl"):
        pid = path.stem
        with open(path) as fh:
            for line in fh:
                if line.strip():
                    entry = json.loads(line)
                    totals.setdefault(pid, []).append(entry.get("attempts_wasted", 0))

    return {pid: sum(vals) / len(vals) for pid, vals in totals.items() if vals}


# ── Private helpers ───────────────────────────────────────────────────────────

def _append(entry: PitfallEntry) -> None:
    settings.pitfall_dir.mkdir(parents=True, exist_ok=True)
    path = settings.pitfall_dir / f"{entry.pattern_id}.jsonl"
    with open(path, "a") as fh:
        fh.write(json.dumps(entry.model_dump()) + "\n")


def _load(pattern_id: str) -> list[dict]:
    path = settings.pitfall_dir / f"{pattern_id}.jsonl"
    if not path.exists():
        return []
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]
