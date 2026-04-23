"""
nano_swarm/re_nano/curriculum.py
─────────────────────────────────
Phases 4 and 5 of the RE Nano pipeline.

Phase 4 — packaging: wraps a validated CodeVariation + SandboxResult into a
CurriculumItem and persists it to data/curriculum/{pattern_id}.json.

Phase 5 — teaching: builds a TeachingContext (few-shot examples) from the
curriculum store that is injected into specialist nano prompts at inference time.

The teaching selection algorithm:
  1. Load all curriculum items for the target chain and vulnerability class
  2. Embed the zone code being audited
  3. Rank items by cosine similarity to the zone
  4. Apply internal diversity enforcement within the selected set
  5. Balance labels: no more than ⌈top_k/3⌉ examples of any single label
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..config import settings
from .schemas import (
    AbstractPattern, Chain, CodeVariation, CurriculumItem, CurriculumLabel,
    SandboxResult, Severity, Stealth, TeachingContext,
)
from .variation_generator import _embed, cosine_distance

log = logging.getLogger(__name__)

# Recommend transitioning from in-context priming to LoRA fine-tune once
# this many sandbox-confirmed examples exist for a pattern.
LORA_THRESHOLD = 50


# ── Phase 4: packaging ────────────────────────────────────────────────────────

def package_item(
    variation: CodeVariation,
    sandbox_result: SandboxResult,
    pattern: AbstractPattern,
    teaching_summary: str,
) -> Optional[CurriculumItem]:
    """
    Package a validated variation into a CurriculumItem.
    Returns None for NEEDS_HUMAN_REVIEW items (held, not added to curriculum).
    """
    if sandbox_result.final_label == CurriculumLabel.NEEDS_HUMAN_REVIEW:
        return None

    return CurriculumItem(
        curriculum_id=variation.variation_id,
        pattern_id=variation.pattern_id,
        chain=variation.chain,
        vuln_class=variation.vuln_class,
        checklist_refs=variation.checklist_refs,
        severity=pattern.severity,
        stealth=pattern.stealth,
        label=sandbox_result.final_label,
        training_weight=sandbox_result.training_weight,
        code=variation.code,
        poc=variation.poc,
        dims=variation.dims,
        embedding=variation.embedding or [],
        teaching_summary=teaching_summary,
        sandbox_confirmed=sandbox_result.confirmed_at is not None,
        attempts_required=sandbox_result.confirmed_at,
        source_seeds=pattern.seed_exploits,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def save_curriculum(items: list[CurriculumItem], pattern_id: str) -> Path:
    """Append curriculum items for one pattern to disk."""
    out = settings.curriculum_dir / f"{pattern_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    # Load existing items so we append rather than overwrite
    existing: list[dict] = []
    if out.exists():
        with open(out) as fh:
            existing = json.load(fh)

    new_ids = {item.curriculum_id for item in items}
    existing = [e for e in existing if e.get("curriculum_id") not in new_ids]
    existing.extend(item.model_dump() for item in items)

    with open(out, "w") as fh:
        json.dump(existing, fh, indent=2, default=str)

    log.info("Saved %d items for %s → %s", len(items), pattern_id, out.name)
    return out


def load_curriculum(pattern_id: str) -> list[CurriculumItem]:
    """Load all curriculum items for one pattern."""
    path = settings.curriculum_dir / f"{pattern_id}.json"
    if not path.exists():
        return []
    with open(path) as fh:
        return [CurriculumItem(**row) for row in json.load(fh)]


def load_all_curriculum(
    chain: Optional[str] = None,
    vuln_class: Optional[str] = None,
    min_weight: float = 0.0,
) -> list[CurriculumItem]:
    """Load all stored curriculum items with optional filters."""
    settings.curriculum_dir.mkdir(parents=True, exist_ok=True)
    items: list[CurriculumItem] = []

    for path in settings.curriculum_dir.glob("*.json"):
        with open(path) as fh:
            for row in json.load(fh):
                item = CurriculumItem(**row)
                if chain and item.chain.value != chain:
                    continue
                if vuln_class and vuln_class not in item.vuln_class:
                    continue
                if item.training_weight < min_weight:
                    continue
                items.append(item)

    return items


def lora_threshold_check(pattern_id: str) -> tuple[bool, int]:
    """
    Returns (should_transition_to_lora, current_confirmed_count).
    Signal to the training pipeline that in-context priming should graduate
    to a periodic LoRA fine-tune for this pattern.
    """
    items = load_curriculum(pattern_id)
    confirmed = sum(1 for i in items if i.sandbox_confirmed or
                    i.label == CurriculumLabel.DESCRIPTION_ONLY)
    return confirmed >= LORA_THRESHOLD, confirmed


# ── Phase 5: teaching ─────────────────────────────────────────────────────────

def build_teaching_context(
    nano_target: str,
    zone_id: str,
    zone_code: str,
    chain: str,
    vuln_class: str,
    top_k: int = 5,
    min_weight: float = 0.7,
) -> TeachingContext:
    """
    Select the most relevant curriculum examples for a specialist nano audit task
    and format them as few-shot messages.

    Selection criteria:
      - cosine similarity to the zone code (primary ranking)
      - internal diversity within the selected set
      - label balance (no label dominates the few-shot set)

    Returns a TeachingContext ready to be prepended to the specialist nano's prompt.
    """
    candidates = load_all_curriculum(chain=chain, vuln_class=vuln_class, min_weight=min_weight)

    # Fall back to all chain items if the specific class has no curriculum yet
    if not candidates:
        candidates = load_all_curriculum(chain=chain, min_weight=min_weight)

    if not candidates:
        return TeachingContext(
            nano_target=nano_target, zone_id=zone_id,
            chain=Chain(chain), vuln_class=vuln_class,
            few_shot_messages=[], curriculum_ids_used=[],
            example_count=0, has_adversarial=False,
        )

    zone_emb = _embed(zone_code)
    ranked = sorted(
        candidates,
        key=lambda i: cosine_distance(zone_emb, i.embedding) if i.embedding else 1.0,
    )

    selected: list[CurriculumItem] = []
    label_counts: dict[str, int] = {}
    selected_embs: list[list[float]] = []
    max_per_label = max(2, top_k // 3)

    for item in ranked:
        if len(selected) >= top_k:
            break
        label_key = item.label.value
        if label_counts.get(label_key, 0) >= max_per_label:
            continue
        if selected_embs and item.embedding:
            if any(cosine_distance(item.embedding, e) < 0.15 for e in selected_embs):
                continue
        selected.append(item)
        label_counts[label_key] = label_counts.get(label_key, 0) + 1
        if item.embedding:
            selected_embs.append(item.embedding)

    messages = _format_few_shot(selected)
    has_adversarial = any(
        item.dims.guard_presence in ("wrong_frame", "inherited_missing")
        for item in selected
    )

    return TeachingContext(
        nano_target=nano_target, zone_id=zone_id,
        chain=Chain(chain), vuln_class=vuln_class,
        few_shot_messages=messages,
        curriculum_ids_used=[i.curriculum_id for i in selected],
        example_count=len(selected),
        has_adversarial=has_adversarial,
    )


def _format_few_shot(items: list[CurriculumItem]) -> list[dict]:
    """Format curriculum items as user/assistant message pairs for few-shot priming."""
    messages: list[dict] = []
    for item in items:
        label_str = {
            CurriculumLabel.CONFIRMED_VULNERABLE: "VULNERABLE",
            CurriculumLabel.CONFIRMED_PROTECTED:  "PROTECTED",
            CurriculumLabel.DESCRIPTION_ONLY:     "VULNERABLE (description-confirmed)",
        }.get(item.label, item.label.value)

        confirmed_note = ""
        if item.sandbox_confirmed:
            confirmed_note = f"\nSandbox: confirmed on attempt {item.attempts_required}"

        adversarial_note = ""
        if item.dims.guard_presence in ("wrong_frame", "inherited_missing"):
            adversarial_note = (
                "\nNote: ADVERSARIAL example — guard prevents exploitation "
                "despite surface appearance"
            )

        messages.append({
            "role": "user",
            "content": (
                f"Audit this {item.chain.value} code for {item.vuln_class}:\n\n"
                f"```\n{item.code[:1500]}\n```"
            ),
        })
        messages.append({
            "role": "assistant",
            "content": (
                f"Assessment: {label_str}\n"
                f"Severity: {item.severity.value}\n"
                f"Checklist refs: {', '.join(item.checklist_refs[:3])}\n"
                f"Finding: {item.teaching_summary}"
                f"{confirmed_note}"
                f"{adversarial_note}"
            ),
        })

    return messages


# ── Store statistics ──────────────────────────────────────────────────────────

def curriculum_stats() -> dict:
    """Return a summary of the full curriculum store."""
    all_items = load_all_curriculum()
    lora_ready: list[dict] = []

    for path in settings.curriculum_dir.glob("*.json"):
        ready, count = lora_threshold_check(path.stem)
        if ready:
            lora_ready.append({"pattern_id": path.stem, "confirmed_count": count})

    by_chain: dict[str, int] = {}
    by_label: dict[str, int] = {}
    for item in all_items:
        by_chain[item.chain.value] = by_chain.get(item.chain.value, 0) + 1
        by_label[item.label.value] = by_label.get(item.label.value, 0) + 1

    return {
        "total_items":          len(all_items),
        "sandbox_confirmed":    sum(1 for i in all_items if i.sandbox_confirmed),
        "total_training_weight": sum(i.training_weight for i in all_items),
        "by_chain":             by_chain,
        "by_label":             by_label,
        "lora_ready_patterns":  lora_ready,
    }
