"""
nano_swarm/re_nano/orchestrator.py
───────────────────────────────────
Wires Phases 1–5 of the RE Nano pipeline and receives Loop 1/2 signals.

Usage:
    from nano_swarm.re_nano.orchestrator import RENano

    re = RENano()
    re.run(max_patterns=3, variations_per_pattern=10)   # pilot run
    re.run()                                              # full run

    # Get teaching context for a specialist nano (called at audit time)
    ctx = re.teaching_context(
        nano="ReentrancyMaster",
        zone_id="zone_001",
        zone_code="function withdraw...",
        chain="ethereum",
        vuln_class="reentrancy",
    )

    # Loop 1 signal: triage rejected a finding
    re.on_triage_rejection(
        pattern_id="ETH-REENTRANCY-003",
        chain="ethereum",
        vuln_class="reentrancy",
        invalidation_code="EG-2",
        explanation="Guard was present via inherited base contract — nano missed it",
    )

    # Loop 2 signal: jury overturned a triage decision
    re.on_jury_overturn(
        pattern_id="ETH-REENTRANCY-003",
        triage_decision="REJECT",
        jury_verdict="CONFIRMED",
        triage_step="EG",
        reason_applied="EG-2",
        correction="CP-1 does not apply when flash loan amplifies profit beyond gas cost",
    )
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

from ..config import settings
from .curriculum import (
    build_teaching_context, curriculum_stats, lora_threshold_check,
    package_item, save_curriculum,
)
from .pattern_extractor import extract_pattern
from .sandbox_validator import validate_variation
from .schemas import AbstractPattern, CurriculumItem, TeachingContext
from .seed_ingestion import build_pattern_id, iter_groups, load_seeds, summarise
from .self_education import (
    attempts_trend, build_pitfall_context,
    log_loop1_rejection, log_loop2_overturn,
    log_sandbox_failure, pitfall_stats,
)
from .variation_generator import generate_variations
from .schemas import FaultType

log = logging.getLogger(__name__)


class RENano:
    """
    Reverse Engineering & Teaching Nano.

    Orchestrates Phases 1–5 and handles Loop 1/2 feedback signals.
    Instantiate once; call run() to populate the curriculum store;
    call teaching_context() at audit time.
    """

    # Cache of loaded / extracted patterns for this session
    _patterns: list[AbstractPattern]

    def __init__(self) -> None:
        settings.ensure_data_dirs()
        self._patterns = []
        self._load_cached_patterns()

    # ── Public: pipeline ──────────────────────────────────────────────────────

    def run(
        self,
        max_patterns: Optional[int] = None,
        variations_per_pattern: Optional[int] = None,
        skip_sandbox: bool = False,
    ) -> dict:
        """
        Run the full RE Nano pipeline:
          Phase 1 — extract abstract patterns from seeds
          Phase 2 — generate diverse code variations per pattern
          Phase 3 — validate variations in sandbox (unless skip_sandbox=True)
          Phase 4 — package validated items
          Phase 5 — curriculum is now ready for teaching (no explicit step needed)

        Args:
            max_patterns:          stop after this many patterns (None = all)
            variations_per_pattern: override VARIATIONS_PER_PATTERN from .env
            skip_sandbox:          skip PoC execution (useful for unit tests)

        Returns:
            Summary dict with statistics.
        """
        n_variations = variations_per_pattern or settings.variations_per_pattern
        start = time.time()

        log.info("=== RE Nano pipeline starting ===")
        seeds = load_seeds(settings.seeds_path)
        summarise(seeds)

        # Phase 1
        self._extract_patterns(seeds, max_patterns)

        # Phases 2–4 per pattern
        all_items: list[CurriculumItem] = []
        for pattern in self._patterns:
            items = self._process_pattern(pattern, n_variations, skip_sandbox)
            all_items.extend(items)

        elapsed = time.time() - start
        stats = curriculum_stats()
        pf = pitfall_stats()

        log.info("=== RE Nano pipeline complete (%.1fs) ===", elapsed)
        log.info("  Patterns:          %d", len(self._patterns))
        log.info("  Curriculum items:  %d", stats["total_items"])
        log.info("  Sandbox confirmed: %d", stats["sandbox_confirmed"])
        log.info("  LoRA-ready:        %d patterns", len(stats["lora_ready_patterns"]))
        log.info("  Pitfall entries:   %d (resolved %.0f%%)",
                 pf["total_entries"], pf["resolved_rate"] * 100)

        return {
            "patterns":         len(self._patterns),
            "curriculum_stats": stats,
            "pitfall_stats":    pf,
            "elapsed_seconds":  round(elapsed, 1),
        }

    # ── Public: teaching ──────────────────────────────────────────────────────

    def teaching_context(
        self,
        nano: str,
        zone_id: str,
        zone_code: str,
        chain: str,
        vuln_class: str,
        top_k: int = 5,
    ) -> TeachingContext:
        """
        Build the few-shot teaching context for a specialist nano.
        Call this before routing scoped code to any specialist nano.
        """
        return build_teaching_context(
            nano_target=nano,
            zone_id=zone_id,
            zone_code=zone_code,
            chain=chain,
            vuln_class=vuln_class,
            top_k=top_k,
        )

    # ── Public: loop feedback ─────────────────────────────────────────────────

    def on_triage_rejection(
        self,
        pattern_id: str,
        chain: str,
        vuln_class: str,
        invalidation_code: str,
        explanation: str,
    ) -> None:
        """
        Loop 1 signal: a specialist nano generated a false positive.
        Logs the mistake class so future generation avoids it.
        """
        log.info("[LOOP 1] Rejection: %s — %s: %s", pattern_id, invalidation_code, explanation)
        log_loop1_rejection(
            pattern_id=pattern_id,
            chain=chain,
            vuln_class=vuln_class,
            invalidation_code=invalidation_code,
            explanation=explanation,
        )

    def on_jury_overturn(
        self,
        pattern_id: str,
        triage_decision: str,
        jury_verdict: str,
        triage_step: str,
        reason_applied: str,
        correction: str,
    ) -> None:
        """
        Loop 2 signal: a jury overturned a triage decision.
        Logs the correction for triage curriculum update.
        """
        log.info("[LOOP 2] Overturn: %s: triage=%s jury=%s — %s",
                 pattern_id, triage_decision, jury_verdict, correction)
        log_loop2_overturn(
            pattern_id=pattern_id,
            triage_decision=triage_decision,
            jury_verdict=jury_verdict,
            triage_step=triage_step,
            reason_applied=reason_applied,
            correction=correction,
        )

    # ── Public: stats ─────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return combined curriculum and pitfall statistics."""
        return {
            "curriculum": curriculum_stats(),
            "pitfalls":   pitfall_stats(),
            "loop3_trend": attempts_trend(),
        }

    # ── Private: per-pattern processing ──────────────────────────────────────

    def _process_pattern(
        self,
        pattern: AbstractPattern,
        n_variations: int,
        skip_sandbox: bool,
    ) -> list[CurriculumItem]:
        """Phases 2–4 for one pattern."""
        log.info("Processing %s [%s] %s", pattern.pattern_id, pattern.chain.value, pattern.vulnerability_class)

        # Inject pitfall context so RE Nano avoids known mistakes
        pitfall_ctx = build_pitfall_context(pattern.pattern_id)
        if pitfall_ctx:
            # Prepended to the pattern object for the variation generator to use
            # (stored transiently — not persisted to disk)
            pattern.__dict__["_pitfall_context"] = pitfall_ctx

        # Phase 2: generate
        variations, _ = generate_variations(
            pattern=pattern,
            target_size=n_variations,
            diversity_threshold=settings.diversity_threshold,
        )

        # Phase 3: sandbox validate
        items: list[CurriculumItem] = []
        confirmed = 0

        for variation in variations:
            if skip_sandbox:
                from .schemas import CurriculumLabel, SandboxResult
                result = SandboxResult(
                    variation_id=variation.variation_id,
                    attempts=[],
                    final_label=CurriculumLabel.NEEDS_HUMAN_REVIEW,
                    training_weight=0.0,
                    notes="Sandbox skipped (skip_sandbox=True)",
                )
            else:
                result = validate_variation(
                    variation=variation,
                    pattern_sandboxable=pattern.sandboxable,
                    chain_fidelity=pattern.sandbox_fidelity,
                )
                # Loop 3: log sandbox failures
                for attempt in result.attempts:
                    if not attempt.succeeded and attempt.fault:
                        if attempt.fault in (FaultType.BAD_POC, FaultType.WRONG_SEQUENCE):
                            log_sandbox_failure(
                                pattern_id=pattern.pattern_id,
                                variation=variation,
                                fault_type=attempt.fault,
                                explanation=attempt.fault_detail or "",
                                fix_applied=f"Revised PoC on attempt {attempt.attempt_number + 1}",
                                attempts_wasted=attempt.attempt_number,
                                resolved=result.confirmed_at is not None,
                            )

            # Phase 4: package
            summary = _make_summary(variation, result)
            item = package_item(variation, result, pattern, summary)
            if item:
                items.append(item)
                if item.sandbox_confirmed:
                    confirmed += 1

        if items:
            save_curriculum(items, pattern.pattern_id)

        ready, total = lora_threshold_check(pattern.pattern_id)
        log.info("  %d items (confirmed=%d, total_in_store=%d%s)",
                 len(items), confirmed, total,
                 " — LoRA threshold met!" if ready else "")

        return items

    # ── Private: pattern caching ──────────────────────────────────────────────

    def _extract_patterns(
        self,
        seeds,
        max_patterns: Optional[int],
    ) -> None:
        """Phase 1: extract patterns not already cached."""
        cache = settings.patterns_dir / "patterns.json"
        if cache.exists():
            log.info("Loading cached patterns from %s", cache)
            with open(cache) as fh:
                self._patterns = [AbstractPattern(**p) for p in json.load(fh)]
            log.info("Loaded %d cached patterns", len(self._patterns))
            return

        log.info("Phase 1: extracting patterns (max=%s)…", max_patterns or "all")
        seq = 1
        for chain, vuln_class, group in iter_groups(seeds):
            if max_patterns and seq > max_patterns:
                break
            loss = sum(s.loss_amount_usd for s in group if s.loss_amount_usd)
            log.info("[%03d] [%s] %s (%d seeds, $%s)",
                     seq, chain, vuln_class, len(group), f"{loss:,}" if loss else "?")
            try:
                p = extract_pattern(chain, vuln_class, group, seq)
                self._patterns.append(p)
                log.info("      ✓ %s", p.pattern_id)
            except Exception as exc:
                log.error("      ✗ FAILED: %s", exc)
            seq += 1
            time.sleep(0.3)

        # Cache to disk
        cache.parent.mkdir(parents=True, exist_ok=True)
        with open(cache, "w") as fh:
            json.dump([p.model_dump() for p in self._patterns], fh, indent=2, default=str)
        log.info("Cached %d patterns → %s", len(self._patterns), cache)

    def _load_cached_patterns(self) -> None:
        cache = settings.patterns_dir / "patterns.json"
        if cache.exists():
            with open(cache) as fh:
                self._patterns = [AbstractPattern(**p) for p in json.load(fh)]


# ── Private helpers ───────────────────────────────────────────────────────────

def _make_summary(variation, result) -> str:
    dims = variation.dims
    label_verb = {
        "vulnerable":   "contains",
        "protected":    "correctly mitigates",
        "adversarial":  "appears to contain but is actually protected against",
    }.get(variation.label.value, "involves")
    confirmed = (
        f" (sandbox confirmed, attempt {result.confirmed_at})"
        if result.confirmed_at else ""
    )
    return (
        f"{dims.function_name}() in a {dims.protocol_type} "
        f"{label_verb} {variation.vuln_class} via {dims.external_call_target} "
        f"with {dims.guard_presence.replace('_', ' ')} guard{confirmed}."
    )
