"""
nano_swarm/specialist_nanos/base.py
─────────────────────────────────────
Base class for all specialist nanos.

Every specialist nano:
  1. Receives scoped code + architecture context from the pipeline orchestrator
  2. Is primed with few-shot examples from the RE Nano curriculum (TeachingContext)
  3. Produces structured findings with evidence, exploit path, and checklist refs
  4. Can emit lateral routing signals for adjacent vulnerability classes

Principle 1 (Nano Trust Minimisation):
  No nano output goes directly to the report. Everything passes through triage.
  Specialist nanos are intentionally biased toward finding — triage is biased
  toward rejection. That tension is the quality filter.

Subclasses must implement:
  NANO_NAME             — unique identifier string
  VULNERABILITY_CLASSES — which bug classes this nano covers
  SUPPORTED_CHAINS      — which chains it knows about
  _build_system_prompt(chain) → str
  _parse_response(api_response, result, chain) → NanoResult
"""
from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from ..llm_client import get_client
from ..re_nano.schemas import TeachingContext

log = logging.getLogger(__name__)


# ── Finding ───────────────────────────────────────────────────────────────────

@dataclass
class LateralSignal:
    """
    Emitted when a nano detects something adjacent to its own domain.
    The pipeline orchestrator processes these after the initial fan-out,
    routing the zone to the indicated nano for a second-pass review.
    """
    route_to: str    # "ReentrancyMaster" | "AccessControlSpecialist" | …
    zone_id:  str
    reason:   str    # one-sentence explanation for the reviewer

    def to_dict(self) -> dict:
        return {"route_to": self.route_to, "zone_id": self.zone_id, "reason": self.reason}


@dataclass
class Finding:
    """A single vulnerability finding produced by a specialist nano."""

    nano:          str
    finding_id:    str
    title:         str
    vuln_class:    str
    chain:         str
    severity:      str            # CRIT | HIGH | MED | LOW
    stealth:       str            # HIGH | MED | LOW
    confidence:    float          # 0.0–1.0 (routing hint only — not ground truth)
    evidence:      dict
    exploit_path:  str
    checklist_refs: list[str]
    fix:           str
    lateral:       Optional[LateralSignal] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {
            "nano":           self.nano,
            "finding_id":     self.finding_id,
            "title":          self.title,
            "vuln_class":     self.vuln_class,
            "chain":          self.chain,
            "severity":       self.severity,
            "stealth":        self.stealth,
            "confidence":     self.confidence,
            "evidence":       self.evidence,
            "exploit_path":   self.exploit_path,
            "checklist_refs": self.checklist_refs,
            "fix":            self.fix,
            "lateral":        self.lateral.to_dict() if self.lateral else None,
        }

    def __repr__(self) -> str:
        return f"Finding({self.finding_id}: {self.severity} {self.vuln_class} [{self.confidence:.2f}])"


@dataclass
class NanoResult:
    """Aggregate output from one specialist nano on one audit zone."""

    nano_name:        str
    zone_id:          str
    chain:            str
    findings:         list[Finding] = field(default_factory=list)
    zones_cleared:    list[str]    = field(default_factory=list)
    lateral_signals:  list[LateralSignal] = field(default_factory=list)
    reasoning_trace:  str          = ""
    ttt_applied:      bool         = False
    teaching_count:   int          = 0    # how many few-shot examples were injected
    error:            Optional[str] = None

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)
        if f.lateral:
            self.lateral_signals.append(f.lateral)

    def to_dict(self) -> dict:
        return {
            "nano":            self.nano_name,
            "zone_id":         self.zone_id,
            "chain":           self.chain,
            "findings":        [f.to_dict() for f in self.findings],
            "zones_cleared":   self.zones_cleared,
            "lateral_signals": [s.to_dict() for s in self.lateral_signals],
            "reasoning_trace": self.reasoning_trace[:400],
            "ttt_applied":     self.ttt_applied,
            "teaching_count":  self.teaching_count,
            "error":           self.error,
        }


# ── Base nano ─────────────────────────────────────────────────────────────────

class BaseSpecialistNano(ABC):
    """
    Abstract base for all specialist nanos.

    Subclasses are biased toward finding. They err on the side of raising
    an issue — triage exists to reject their output. A finding that triage
    correctly rejects is still useful: it becomes training data (Loop 1).
    """

    NANO_NAME:             str       = "BaseNano"
    VULNERABILITY_CLASSES: list[str] = []
    SUPPORTED_CHAINS:      list[str] = ["ethereum", "solana", "sui", "bitcoin"]

    # ── Public: analyse ───────────────────────────────────────────────────────

    def analyse(
        self,
        zone_id:          str,
        scoped_code:      str,
        chain:            str,
        code_reader:      dict,
        arch_context:     dict,
        teaching_context: Optional[TeachingContext] = None,
        finding_start:    int = 1,
    ) -> NanoResult:
        """
        Analyse one high-risk zone for the vulnerability classes this nano covers.

        Args:
            zone_id:          identifier for this code zone (e.g. "zone_001")
            scoped_code:      the extracted code for this zone
            chain:            "ethereum" | "solana" | "sui" | "bitcoin"
            code_reader:      structured output from the Code Reader
            arch_context:     routing context from the Architecture Synthesizer
            teaching_context: few-shot examples from the RE Nano curriculum
            finding_start:    numbering offset for finding IDs

        Returns:
            NanoResult with findings and lateral signals.
        """
        result = NanoResult(nano_name=self.NANO_NAME, zone_id=zone_id, chain=chain)

        if chain not in self.SUPPORTED_CHAINS:
            result.zones_cleared.append(zone_id)
            return result

        system = self._build_system_prompt(chain)
        messages: list[dict] = []

        # Inject RE Nano few-shot teaching context before the analysis request
        if teaching_context and teaching_context.few_shot_messages:
            messages.extend(teaching_context.few_shot_messages)
            result.teaching_count = teaching_context.example_count

        messages.append({
            "role": "user",
            "content": self._build_user_prompt(
                zone_id, scoped_code, chain, code_reader, arch_context, finding_start
            ),
        })

        try:
            client = get_client()
            # Build a single user message combining all few-shot + analysis request
            # (DeepSeek/OpenAI format supports multi-turn system + messages)
            if len(messages) == 1:
                response = client.chat(system=system, user=messages[0]["content"],
                                       max_tokens=4000)
            else:
                # Flatten multi-turn for APIs that expect system + single user
                flattened = "\n\n---\n\n".join(
                    f"[{m['role'].upper()}]\n{m['content']}" for m in messages
                )
                response = client.chat(system=system, user=flattened, max_tokens=4000)

            result = self._parse_response(response.text, result, chain)
        except Exception as exc:
            log.error("%s error on %s: %s", self.NANO_NAME, zone_id, exc)
            result.error = str(exc)

        return result

    # ── Shared prompt builder ──────────────────────────────────────────────────

    def _build_user_prompt(
        self,
        zone_id:      str,
        scoped_code:  str,
        chain:        str,
        code_reader:  dict,
        arch_context: dict,
        finding_start: int,
    ) -> str:
        fns = code_reader.get("functions", [])
        fn_names = (
            ", ".join(
                f.get("name", str(f)) if isinstance(f, dict) else str(f)
                for f in fns[:10]
            )
            or "see code"
        )

        return (
            f"Zone: {zone_id}\n"
            f"Chain: {chain}\n"
            f"Functions: {fn_names}\n"
            f"Focus hint: {arch_context.get('focus_hint', 'full audit')}\n\n"
            f"Code:\n```\n{scoped_code}\n```\n\n"
            f"Audit for: {', '.join(self.VULNERABILITY_CLASSES)}\n"
            f"Start finding IDs at {self.NANO_NAME[:2].upper()}-{finding_start:03d}.\n"
            "Output a JSON array of findings. Return [] if the zone is clear."
        )

    # ── Shared JSON extractor ─────────────────────────────────────────────────

    def _extract_json(self, text: str) -> list[dict]:
        """
        Extract a JSON findings array from the model's raw text output.
        Handles models that add markdown fences despite being told not to.
        """
        text = text.strip()

        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            inner = text.split("```")[1].split("```")[0].strip()
            if inner:
                text = inner

        if not text:
            return []

        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return parsed.get("findings", [parsed])
        except json.JSONDecodeError:
            import re
            match = re.search(r"\[.*?\]", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass

        log.debug("%s: could not extract JSON findings from response", self.NANO_NAME)
        return []

    # ── Abstract interface ─────────────────────────────────────────────────────

    @abstractmethod
    def _build_system_prompt(self, chain: str) -> str:
        """Return the system prompt for this nano on the given chain."""

    @abstractmethod
    def _parse_response(self, raw_text: str, result: NanoResult, chain: str) -> NanoResult:
        """Parse the model's raw text output into a NanoResult."""
