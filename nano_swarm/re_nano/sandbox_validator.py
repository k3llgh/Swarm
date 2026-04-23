"""
nano_swarm/re_nano/sandbox_validator.py
────────────────────────────────────────
Phase 3 of the RE Nano pipeline: sandbox validation.

The oracle: if a PoC executes successfully in a chain-local sandbox,
the vulnerability is confirmed. If all three attempts fail, the example
is classified as protected. If the sandbox cannot model the condition,
the example is held for human review.

Critical design: a failed PoC does not automatically mean the vulnerability
is absent. Fault diagnosis distinguishes three failure causes:

  bad_poc           — vulnerability exists; the exploit code is wrong
  wrong_sequence    — attack is conceptually correct; entry point is wrong
  sandbox_limitation — condition requires mainnet state or live oracle

Without this distinction the system learns to write conservative PoCs —
which never fail but also never confirm real vulnerabilities.

Sandbox environments (requires respective tools to be installed):
  Ethereum  — Foundry / Anvil (mainnet fork)
  Solana    — solana-test-validator + Anchor test runner (stub in Phase 1)
  Sui       — sui move test (stub in Phase 1)
  Bitcoin   — no sandbox; description-only (chain fidelity 0.70)
"""
from __future__ import annotations

import logging
import subprocess
import tempfile
import textwrap
from pathlib import Path
from shutil import which
from typing import Optional

from ..llm_client import get_client
from .schemas import (
    Chain, CodeVariation, CurriculumLabel, FaultType,
    SandboxAttempt, SandboxResult,
)
from .seed_ingestion import CHAIN_FIDELITY

log = logging.getLogger(__name__)

MAX_ATTEMPTS = 3
SANDBOX_TIMEOUT_SECONDS = 60


# ── Tool availability (checked once at module load) ───────────────────────────

def _tool_available(name: str) -> bool:
    return which(name) is not None


TOOL_AVAILABLE: dict[str, bool] = {
    "forge":  _tool_available("forge"),
    "anchor": _tool_available("anchor"),
    "sui":    _tool_available("sui"),
}


# ── Public interface ──────────────────────────────────────────────────────────

def validate_variation(
    variation: CodeVariation,
    pattern_sandboxable: bool = True,
    chain_fidelity: float = 1.0,
) -> SandboxResult:
    """
    Validate one code variation by attempting to execute its PoC in a sandbox.

    Logic:
      - Bitcoin or non-sandboxable → DESCRIPTION_ONLY (weight 0.70)
      - Tool not installed         → NEEDS_HUMAN_REVIEW (weight 0.00)
      - Protected label            → confirm guard holds; PoC should fail
      - Vulnerable/adversarial     → up to MAX_ATTEMPTS with fault diagnosis

    Returns a SandboxResult with final_label and training_weight.
    """
    chain = variation.chain.value

    # Bitcoin: no executable sandbox in Phase 1
    if chain == "bitcoin" or not pattern_sandboxable:
        return SandboxResult(
            variation_id=variation.variation_id,
            attempts=[],
            final_label=CurriculumLabel.DESCRIPTION_ONLY,
            training_weight=CHAIN_FIDELITY["bitcoin"],
            confirmed_at=None,
            notes="Bitcoin — description-only; no regtest sandbox in Phase 1",
        )

    # Check tool availability
    tool = {"ethereum": "forge", "solana": "anchor", "sui": "sui"}.get(chain)
    if tool and not TOOL_AVAILABLE.get(tool, False):
        log.warning("Sandbox tool '%s' not found — marking for human review", tool)
        return SandboxResult(
            variation_id=variation.variation_id,
            attempts=[],
            final_label=CurriculumLabel.NEEDS_HUMAN_REVIEW,
            training_weight=0.0,
            confirmed_at=None,
            notes=f"Required tool '{tool}' not installed. "
                  f"Install Foundry (Ethereum) / Anchor (Solana) / Sui CLI.",
        )

    # Protected examples: confirm the guard holds
    if variation.label.value == "protected":
        return _validate_protected(variation, chain_fidelity)

    # Vulnerable / adversarial: attempt exploit with fault diagnosis
    return _attempt_exploit(variation, chain_fidelity)


# ── Exploit attempt loop ──────────────────────────────────────────────────────

def _attempt_exploit(variation: CodeVariation, chain_fidelity: float) -> SandboxResult:
    """Try to execute the PoC up to MAX_ATTEMPTS times, with fault diagnosis."""
    poc = variation.poc
    if not poc:
        return SandboxResult(
            variation_id=variation.variation_id,
            attempts=[],
            final_label=CurriculumLabel.NEEDS_HUMAN_REVIEW,
            training_weight=0.0,
            confirmed_at=None,
            notes="No PoC was generated for this variation",
        )

    attempts: list[SandboxAttempt] = []

    for n in range(1, MAX_ATTEMPTS + 1):
        log.debug("  Sandbox attempt %d/%d for %s", n, MAX_ATTEMPTS, variation.variation_id)
        success, output, revert = _run_sandbox(variation.chain.value, variation.code, poc)

        attempt = SandboxAttempt(
            attempt_number=n,
            poc_code=poc,
            succeeded=success,
            funds_moved="confirmed by sandbox" if success else None,
            revert_reason=revert,
            error_output=output[:400] if not success else None,
            fault=None,
            fault_detail=None,
        )

        if success:
            attempts.append(attempt)
            # Execution confirmed — highest training weight
            base_weight = 3.0
            return SandboxResult(
                variation_id=variation.variation_id,
                attempts=attempts,
                final_label=CurriculumLabel.CONFIRMED_VULNERABLE,
                training_weight=base_weight * chain_fidelity,
                confirmed_at=n,
                notes=f"PoC executed successfully on attempt {n}",
            )

        # Failed — diagnose before the next attempt
        if n < MAX_ATTEMPTS:
            fault_type, detail, hint = _diagnose(variation, poc, output, revert, n)
            attempt.fault = fault_type
            attempt.fault_detail = detail
            attempts.append(attempt)

            if fault_type == FaultType.SANDBOX_LIMITATION:
                return SandboxResult(
                    variation_id=variation.variation_id,
                    attempts=attempts,
                    final_label=CurriculumLabel.NEEDS_HUMAN_REVIEW,
                    training_weight=0.0,
                    confirmed_at=None,
                    notes=f"Sandbox limitation on attempt {n}: {detail}",
                )
            if hint and fault_type in (FaultType.BAD_POC, FaultType.WRONG_SEQUENCE):
                poc = _revise_poc(variation, poc, hint, n)
        else:
            attempt.fault = FaultType.TRULY_ABSENT
            attempt.fault_detail = f"{MAX_ATTEMPTS} independent attempts all failed"
            attempts.append(attempt)

    # All attempts exhausted without success
    return SandboxResult(
        variation_id=variation.variation_id,
        attempts=attempts,
        final_label=CurriculumLabel.CONFIRMED_PROTECTED,
        training_weight=1.0 * chain_fidelity,
        confirmed_at=None,
        notes=f"All {MAX_ATTEMPTS} PoC attempts failed — classified as protected",
    )


def _validate_protected(variation: CodeVariation, chain_fidelity: float) -> SandboxResult:
    """
    Confirm the guard holds: run the PoC and verify it FAILS.
    If the PoC unexpectedly succeeds, reclassify as vulnerable.
    """
    if not variation.poc:
        return SandboxResult(
            variation_id=variation.variation_id,
            attempts=[],
            final_label=CurriculumLabel.CONFIRMED_PROTECTED,
            training_weight=1.0 * chain_fidelity,
            notes="Protected example — no PoC to run",
        )

    success, output, revert = _run_sandbox(
        variation.chain.value, variation.code, variation.poc
    )
    attempt = SandboxAttempt(
        attempt_number=1,
        poc_code=variation.poc,
        succeeded=success,
        funds_moved=None,
        revert_reason=revert,
        error_output=output[:400] if success else None,
        fault=None,
        fault_detail=None,
    )

    if success:
        log.warning("Protected example %s was actually exploitable — reclassified",
                    variation.variation_id)
        return SandboxResult(
            variation_id=variation.variation_id,
            attempts=[attempt],
            final_label=CurriculumLabel.CONFIRMED_VULNERABLE,
            training_weight=3.0 * chain_fidelity,
            confirmed_at=1,
            notes="WARNING: 'protected' label was wrong; example is exploitable — reclassified",
        )

    return SandboxResult(
        variation_id=variation.variation_id,
        attempts=[attempt],
        final_label=CurriculumLabel.CONFIRMED_PROTECTED,
        training_weight=1.0 * chain_fidelity,
        notes="Guard confirmed: exploit failed as expected",
    )


# ── Chain-specific sandbox runners ────────────────────────────────────────────

def _run_sandbox(
    chain: str,
    contract: str,
    poc: str,
) -> tuple[bool, str, Optional[str]]:
    """
    Execute a PoC against the contract in the appropriate sandbox.
    Returns (success, full_output, revert_reason).
    """
    if chain == "ethereum":
        return _run_foundry(contract, poc)
    # Solana and Sui sandbox integration: placeholder for Phase 2
    return False, f"Sandbox for {chain} not yet implemented (Phase 2)", None


def _run_foundry(contract: str, poc: str) -> tuple[bool, str, Optional[str]]:
    """
    Execute a Foundry test in a temporary directory.
    The PoC must contain a test function named `test_exploit*`.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "test").mkdir()

        (root / "src" / "Target.sol").write_text(contract)
        (root / "test" / "Exploit.t.sol").write_text(textwrap.dedent(f"""
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            import "forge-std/Test.sol";
            import "../src/Target.sol";

            {poc}
        """))
        (root / "foundry.toml").write_text(
            '[profile.default]\nsrc="src"\nout="out"\nlibs=["lib"]\n'
        )

        try:
            result = subprocess.run(
                ["forge", "test", "--match-test", "test_exploit", "-vvv"],
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=SANDBOX_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return False, "Forge test timed out", "timeout"
        except FileNotFoundError:
            return False, "forge not found in PATH", "tool_missing"

        output = result.stdout + result.stderr
        success = result.returncode == 0 and "[PASS]" in output

        revert: Optional[str] = None
        for line in output.splitlines():
            if "revert" in line.lower() or "reason:" in line.lower():
                revert = line.strip()
                break

        return success, output, revert


# ── Fault diagnosis and PoC revision ─────────────────────────────────────────

_DIAGNOSIS_SYSTEM = """\
You are analysing a failed blockchain exploit proof-of-concept.
Determine WHY the PoC failed. Output JSON only — no markdown, no preamble.

{
  "fault_type": "bad_poc" | "wrong_sequence" | "sandbox_limitation" | "truly_absent",
  "confidence": <float 0.0–1.0>,
  "explanation": "<one sentence>",
  "revised_poc_hint": "<specific change for next attempt, or null if truly_absent>"
}

Fault types:
  bad_poc:            vulnerability exists; exploit code is incorrect
  wrong_sequence:     attack is correct conceptually; transaction ordering is wrong
  sandbox_limitation: condition requires mainnet state, live oracle, or specific block
  truly_absent:       the vulnerability is genuinely not present in the code
"""


def _diagnose(
    variation: CodeVariation,
    poc: str,
    error_output: str,
    revert_reason: Optional[str],
    attempt_number: int,
) -> tuple[FaultType, str, Optional[str]]:
    """
    Ask the LLM to classify a PoC failure.
    Returns (fault_type, explanation, revised_poc_hint).
    """
    client = get_client()
    user = (
        f"Contract (first 2000 chars):\n```\n{variation.code[:2000]}\n```\n\n"
        f"Failed PoC (attempt {attempt_number}):\n```\n{poc[:1500]}\n```\n\n"
        f"Error output:\n{error_output[:800]}\n"
        f"Revert reason: {revert_reason or 'none'}\n\n"
        f"Vulnerability class: {variation.vuln_class}\n"
        f"Generator label: {variation.label.value}\n\n"
        "Why did the PoC fail?"
    )

    try:
        response = client.chat(system=_DIAGNOSIS_SYSTEM, user=user,
                               max_tokens=400, temperature=0.1)
        data = response.as_json()
        return (
            FaultType(data.get("fault_type", "truly_absent")),
            data.get("explanation", ""),
            data.get("revised_poc_hint"),
        )
    except Exception as exc:
        log.debug("Fault diagnosis error: %s", exc)
        return FaultType.TRULY_ABSENT, "Diagnosis failed — defaulting to absent", None


def _revise_poc(
    variation: CodeVariation,
    original_poc: str,
    hint: str,
    attempt_number: int,
) -> str:
    """Ask the LLM to revise the PoC based on the fault diagnosis hint."""
    lang = {
        Chain.ETHEREUM: "Foundry test (Solidity)",
        Chain.SOLANA:   "Anchor TypeScript test",
        Chain.SUI:      "Sui Move test",
    }.get(variation.chain, "Foundry test")

    client = get_client()
    user = (
        f"The following {lang} PoC failed on attempt {attempt_number}.\n\n"
        f"Contract:\n```\n{variation.code[:1800]}\n```\n\n"
        f"Failed PoC:\n```\n{original_poc[:1200]}\n```\n\n"
        f"Diagnosis hint: {hint}\n\n"
        "Output ONLY the revised PoC code — no explanation."
    )

    try:
        response = client.chat(system="You revise failed exploit PoCs.",
                               user=user, max_tokens=2000, temperature=0.3)
        return response.text.strip()
    except Exception:
        return original_poc  # if revision fails, retry with the same PoC
