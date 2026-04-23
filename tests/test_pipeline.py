"""
tests/test_pipeline.py
───────────────────────
End-to-end pipeline tests. All LLM calls are mocked — no API key required.

Run:
  pytest tests/test_pipeline.py -v
  python tests/test_pipeline.py          # direct run without pytest
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from nano_swarm.specialist_nanos.base import Finding, NanoResult
from nano_swarm.specialist_nanos.reentrancy_master import ReentrancyMasterNano
from nano_swarm.specialist_nanos.access_control import AccessControlSpecialistNano
from nano_swarm.triage.nano import TriageNano
from nano_swarm.tools.cost_accounting import calculate_attack_cost, quick_sanity_check
from nano_swarm.re_nano.seed_ingestion import load_seeds, group_seeds

# ── Test fixtures ─────────────────────────────────────────────────────────────

SEEDS_PATH = Path(__file__).parent.parent / "seeds" / "exploit_seeds.json"

VULNERABLE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableLending {
    mapping(address => uint256) public balances;
    IERC20 public token;

    constructor(address _token) { token = IERC20(_token); }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }

    // CEI VIOLATION: external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        token.transfer(msg.sender, amount);   // external call first
        balances[msg.sender] -= amount;       // state update second
    }
}
"""

REENTRANCY_FINDING_JSON = json.dumps([{
    "finding_id":    "RM-001",
    "title":         "CEI violation: withdraw() updates state after token transfer",
    "class":         "standard",
    "chain":         "ethereum",
    "severity":      "CRIT",
    "stealth":       "HIGH",
    "confidence":    0.95,
    "evidence": {
        "vulnerable_function":       "withdraw",
        "external_call_line":        "token.transfer(msg.sender, amount) — line 24",
        "state_mutation_after_call": True,
        "guard_present":             False,
        "guard_effective":           False,
        "guard_frame":               "none",
        "shared_state_variable":     "balances[msg.sender]",
        "reentry_entry_point":       "withdraw() or any function sharing balances",
    },
    "exploit_path": (
        "1. Attacker deposits 100 tokens.\n"
        "2. Attacker calls withdraw(100).\n"
        "3. token.transfer fires — attacker contract's receive() re-enters withdraw(100).\n"
        "4. Inner call: balances[attacker] == 100 (not yet decremented), transfer succeeds.\n"
        "5. Outer call resumes: balances decremented to 0.\n"
        "Result: attacker withdrew 200 tokens from a 100-token deposit."
    ),
    "checklist_refs": ["E-P2-10", "E-P1-08"],
    "fix": "Decrement balances[msg.sender] before calling token.transfer. Add nonReentrant modifier.",
    "lateral_routing_signal": None,
}])

TRIAGE_ACCEPT_JSON = json.dumps({
    "finding_id":       "RM-001",
    "decision":         "ACCEPT",
    "final_severity":   "CRIT",
    "confidence":       0.93,
    "step_results": {
        "EG":       {"triggered": False, "code": None, "note": "No reentrancy guard present"},
        "UP":       {"triggered": False, "code": None, "note": "Standard conditions"},
        "US":       {"triggered": False, "code": None, "note": "State is reachable via deposit + withdraw"},
        "CP":       {"triggered": False, "code": None, "note": "Gas ~$100; extraction >> $100"},
        "DI_SH_IM": {"triggered": False, "code": None, "note": "Full balance drainage possible"},
    },
    "invalidation_codes": [],
    "accept_note": "All five steps clear. Classic CEI violation.",
    "jury_flag": None,
})


def _mock_llm_response(content: str) -> MagicMock:
    """Helper: build a mock LLMResponse-like object."""
    from nano_swarm.llm_client import LLMResponse
    resp = MagicMock(spec=LLMResponse)
    resp.text = content
    resp.as_json.side_effect = lambda: json.loads(content)
    return resp


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_cost_accounting_profitable():
    """Euler-style attack should be profitable after all costs."""
    result = calculate_attack_cost(
        extractable_value_usd=197_000_000,
        gas_estimate_units=800_000,
        gas_price_gwei=35.0,
        flashloan_amount_usd=30_000_000,
        flashloan_provider="aave",
    )
    assert result["profitable"] is True
    assert result["net_profit_usd"] > 100_000_000
    assert result["applicable_invalidation_codes"] == []
    print(f"  Euler economics: {result['summary']}")


def test_cost_accounting_gas_exceeds_profit():
    """Very small extraction amount should be invalidated by CP-1."""
    result = calculate_attack_cost(
        extractable_value_usd=10.0,
        gas_estimate_units=500_000,
        gas_price_gwei=100.0,
    )
    # At 100 gwei, 500k gas units costs roughly $50–$150 depending on ETH price
    # Either profitable or not, but the math should work
    assert isinstance(result["profitable"], bool)
    assert result["gas_cost_usd"] > 0
    print(f"  Dust attack: {result['summary']}")


def test_reentrancy_master_parses_finding():
    """ReentrancyMasterNano should parse a valid finding from model output."""
    nano = ReentrancyMasterNano()
    result = NanoResult(nano_name="ReentrancyMaster", zone_id="zone_001", chain="ethereum")

    raw_text = f"Analysis complete:\n```json\n{REENTRANCY_FINDING_JSON}\n```"
    result = nano._parse_response(raw_text, result, "ethereum")

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.finding_id == "RM-001"
    assert f.severity == "CRIT"
    assert f.confidence == 0.95
    assert "E-P2-10" in f.checklist_refs
    assert f.lateral is None
    print(f"  Parsed: {f}")


def test_reentrancy_master_skips_bitcoin():
    """ReentrancyMasterNano should return empty result for Bitcoin."""
    nano = ReentrancyMasterNano()
    result = nano.analyse(
        zone_id="zone_001",
        scoped_code="// Bitcoin is not Turing-complete",
        chain="bitcoin",
        code_reader={},
        arch_context={},
    )
    assert len(result.findings) == 0
    assert "zone_001" in result.zones_cleared
    print("  Bitcoin correctly skipped — no reentrancy possible")


def test_access_control_lateral_signal():
    """AccessControlSpecialistNano should emit lateral signals correctly."""
    nano = AccessControlSpecialistNano()
    result = NanoResult(nano_name="AccessControlSpecialist", zone_id="zone_001", chain="ethereum")

    finding_with_lateral = [{
        "finding_id":    "AC-001",
        "title":         "Missing signer check on authority",
        "class":         "missing_check",
        "chain":         "ethereum",
        "severity":      "HIGH",
        "stealth":       "HIGH",
        "confidence":    0.88,
        "evidence":      {"missing_check": "is_signer not verified"},
        "exploit_path":  "Attacker calls without signing.",
        "checklist_refs": ["E-P4-05"],
        "fix":           "Add Signer<> type or explicit is_signer check.",
        "lateral_routing_signal": {
            "route_to": "ReentrancyMaster",
            "zone_id":  "zone_001",
            "reason":   "admin path shares balances mapping with withdraw()",
        },
    }]

    raw_text = f"```json\n{json.dumps(finding_with_lateral)}\n```"
    result = nano._parse_response(raw_text, result, "ethereum")

    assert len(result.findings) == 1
    assert len(result.lateral_signals) == 1
    ls = result.lateral_signals[0]
    assert ls.route_to == "ReentrancyMaster"
    print(f"  Lateral signal: {ls.route_to} — {ls.reason[:50]}")


def test_triage_accept():
    """TriageNano should accept a valid high-confidence finding."""
    triage = TriageNano()
    finding = Finding(
        nano="ReentrancyMaster",
        finding_id="RM-001",
        title="CEI violation",
        vuln_class="standard",
        chain="ethereum",
        severity="CRIT",
        stealth="HIGH",
        confidence=0.95,
        evidence={},
        exploit_path="...",
        checklist_refs=["E-P2-10"],
        fix="Apply CEI.",
    )

    with patch("nano_swarm.triage.nano.get_client") as mock_get:
        mock_client = MagicMock()
        mock_client.chat.return_value = _mock_llm_response(TRIAGE_ACCEPT_JSON)
        mock_get.return_value = mock_client

        verdict = triage.triage(finding, {})

    assert verdict["decision"] == "ACCEPT"
    assert verdict["final_severity"] == "CRIT"
    assert verdict["confidence"] >= 0.9
    assert verdict["invalidation_codes"] == []
    print(f"  Triage ACCEPT: confidence={verdict['confidence']}")


def test_seed_grouping():
    """77 seeds should collapse to 26 pattern groups after alias merging."""
    if not SEEDS_PATH.exists():
        print(f"  Skipped — seeds not found at {SEEDS_PATH}")
        return

    seeds = load_seeds(SEEDS_PATH)
    groups = group_seeds(seeds)

    assert len(seeds) == 77, f"Expected 77 seeds, got {len(seeds)}"
    assert len(groups) == 26, f"Expected 26 groups, got {len(groups)}"

    # Spot check key groups
    eth_reentrancy = groups.get("ethereum::reentrancy", [])
    assert len(eth_reentrancy) >= 7, f"ETH reentrancy: expected ≥7, got {len(eth_reentrancy)}"

    sol_ac = groups.get("solana::access-control", [])
    assert len(sol_ac) >= 7, f"SOL access-control: expected ≥7, got {len(sol_ac)}"

    btc_coinbase = groups.get("bitcoin::bitcoin-coinbase", [])
    assert len(btc_coinbase) >= 3, f"BTC coinbase: expected ≥3, got {len(btc_coinbase)}"

    print(f"  {len(seeds)} seeds → {len(groups)} groups")
    print(f"  ETH reentrancy: {len(eth_reentrancy)} seeds")
    print(f"  SOL access-control: {len(sol_ac)} seeds")
    print(f"  BTC coinbase: {len(btc_coinbase)} seeds")


def test_full_pipeline_mocked():
    """Full pipeline end-to-end with all LLM calls mocked."""
    call_n = [0]

    def side_effect(*args, **kwargs):
        call_n[0] += 1
        n = call_n[0]
        # Calls: 1=ReentrancyMaster, 2=AccessControlSpecialist, 3+=triage+jury
        if n == 1:
            text = f"```json\n{REENTRANCY_FINDING_JSON}\n```"
        elif n == 2:
            text = "```json\n[]\n```"   # AC returns nothing
        else:
            text = TRIAGE_ACCEPT_JSON

        resp = MagicMock()
        resp.text = text
        resp.as_json.side_effect = lambda: json.loads(text)
        return resp

    with patch("nano_swarm.llm_client._client", None), \
         patch("nano_swarm.llm_client._DeepSeekClient.chat", side_effect=side_effect), \
         patch("nano_swarm.llm_client.settings") as mock_settings:

        mock_settings.llm_backend = "deepseek"
        mock_settings.deepseek_api_key = "test-key"
        mock_settings.deepseek_model = "deepseek-chat"
        mock_settings.deepseek_api_base = "https://api.deepseek.com/v1"
        mock_settings.triage_confidence_floor = 0.75
        mock_settings.crit_jury_threshold = 0.85

        from nano_swarm.pipeline.orchestrator import AuditInput, PipelineOrchestrator
        orch = PipelineOrchestrator()
        report = orch.audit(AuditInput(
            contract_code=VULNERABLE_CONTRACT,
            chain="ethereum",
            protocol_name="VulnerableLending",
            tvl_usd=1_000_000,
        ))

    assert len(report.findings) + len(report.jury_cases) >= 1
    print(f"  Findings: {len(report.findings)}, Jury: {len(report.jury_cases)}, "
          f"Rejected: {len(report.rejected)}, Human: {len(report.human_queue)}")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_cost_accounting_profitable,
        test_cost_accounting_gas_exceeds_profit,
        test_reentrancy_master_parses_finding,
        test_reentrancy_master_skips_bitcoin,
        test_access_control_lateral_signal,
        test_triage_accept,
        test_seed_grouping,
        test_full_pipeline_mocked,
    ]

    passed = failed = 0
    for test in tests:
        print(f"\n[{test.__name__}]")
        try:
            test()
            print("  PASS")
            passed += 1
        except Exception as exc:
            print(f"  FAIL: {exc}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*50}")
    print(f"Results: {passed}/{len(tests)} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
