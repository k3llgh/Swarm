"""
nano_swarm/tools/cost_accounting.py
─────────────────────────────────────
Deterministic attack economics calculator.

This is a Python function, not a language model. Language models are
unreliable at arithmetic — a nano claiming $2.3M profit when the real
number is $23K is worse than no calculation because triage will trust
the wrong number.

DeepSeek V3 (the orchestrator) calls this as a tool before triage.
The result is passed verbatim to the Triage Nano for Step 4 (CP checks).

Flash loan fees (current, as of 2025):
  Aave V3:     0.09%
  Uniswap V3:  0.05%
  Balancer:    0.00% (governance-controlled premium pools may differ)
  dYdX:        0.00%

Slippage model:
  Price impact ≈ swap_amount / (2 × pool_liquidity)   [constant-product approximation]
  This is the expected slippage, not the worst case.
"""
from __future__ import annotations

import logging
from typing import Optional

log = logging.getLogger(__name__)

# Flash loan fee rates by provider (fractions, not percentages)
_FLASHLOAN_FEES: dict[str, float] = {
    "aave":       0.0009,
    "aave_v3":    0.0009,
    "uniswap_v3": 0.0005,
    "balancer":   0.0,
    "dydx":       0.0,
}

# ETH price fallback — used when the live feed is unavailable
_ETH_PRICE_FALLBACK_USD = 3_500.0


def get_eth_price() -> float:
    """Fetch live ETH/USD price. Returns a fallback constant on any error."""
    try:
        import requests
        resp = requests.get(
            "https://api.coingecko.com/api/v3/simple/price"
            "?ids=ethereum&vs_currencies=usd",
            timeout=5,
        )
        return float(resp.json()["ethereum"]["usd"])
    except Exception:
        log.debug("ETH price fetch failed — using fallback $%s", _ETH_PRICE_FALLBACK_USD)
        return _ETH_PRICE_FALLBACK_USD


def calculate_attack_cost(
    extractable_value_usd: float,
    gas_estimate_units: int,
    gas_price_gwei: float,
    flashloan_amount_usd: float = 0.0,
    flashloan_provider: str = "aave",
    required_swaps: Optional[list[dict]] = None,
    capital_lockup_usd: float = 0.0,
    lockup_days: int = 0,
    annual_yield_rate: float = 0.05,
) -> dict:
    """
    Calculate the real economics of a proposed attack.

    Args:
        extractable_value_usd:  maximum value the attacker can extract ($)
        gas_estimate_units:     total gas units across all attack transactions
        gas_price_gwei:         current gas price in gwei
        flashloan_amount_usd:   amount borrowed via flash loan (0 if none)
        flashloan_provider:     "aave" | "uniswap_v3" | "balancer" | "dydx"
        required_swaps:         list of {"amount_usd": float, "pool_liquidity_usd": float}
                                representing each swap needed for the attack
        capital_lockup_usd:     capital the attacker must lock for the duration
        lockup_days:            number of days the capital is locked
        annual_yield_rate:      opportunity cost rate (default 5% / year)

    Returns:
        Dict with itemised costs, net profit, and applicable CP invalidation codes.
    """
    eth_price = get_eth_price()

    # Gas cost
    gas_cost_usd = gas_estimate_units * gas_price_gwei * 1e-9 * eth_price

    # Flash loan fee
    fee_rate = _FLASHLOAN_FEES.get(flashloan_provider.lower(), 0.0009)
    flashloan_fee_usd = flashloan_amount_usd * fee_rate

    # Swap slippage (constant-product approximation)
    slippage_usd = 0.0
    for swap in (required_swaps or []):
        amount = float(swap.get("amount_usd", 0))
        liquidity = float(swap.get("pool_liquidity_usd", 1))
        if liquidity > 0:
            impact = amount / (2.0 * liquidity)
            slippage_usd += amount * min(impact, 1.0)   # capped at 100% slippage

    # Opportunity cost
    opportunity_usd = (
        capital_lockup_usd * annual_yield_rate * (lockup_days / 365.0)
        if lockup_days > 0 else 0.0
    )

    total_cost_usd = gas_cost_usd + flashloan_fee_usd + slippage_usd + opportunity_usd
    net_profit_usd = extractable_value_usd - total_cost_usd
    profitable = net_profit_usd > 0
    roi = net_profit_usd / total_cost_usd if total_cost_usd > 0 else 0.0

    # Map to CP invalidation codes
    codes: list[str] = []
    if gas_cost_usd >= extractable_value_usd:
        codes.append("CP-1")
    if flashloan_fee_usd >= extractable_value_usd:
        codes.append("CP-2")
    if slippage_usd >= extractable_value_usd * 0.5:
        codes.append("CP-3")
    if opportunity_usd >= extractable_value_usd:
        codes.append("CP-4")

    return {
        "extractable_value_usd":          round(extractable_value_usd, 2),
        "gas_cost_usd":                   round(gas_cost_usd, 2),
        "flashloan_fee_usd":              round(flashloan_fee_usd, 2),
        "slippage_cost_usd":              round(slippage_usd, 2),
        "opportunity_cost_usd":           round(opportunity_usd, 2),
        "total_cost_usd":                 round(total_cost_usd, 2),
        "net_profit_usd":                 round(net_profit_usd, 2),
        "profitable":                     profitable,
        "roi":                            round(roi, 3),
        "eth_price_usd":                  round(eth_price, 2),
        "applicable_invalidation_codes":  codes,
        "summary": (
            f"Extracts ${extractable_value_usd:,.0f}, costs ${total_cost_usd:,.0f} "
            f"(gas=${gas_cost_usd:,.0f}, flashloan=${flashloan_fee_usd:,.0f}, "
            f"slippage=${slippage_usd:,.0f}). "
            f"Net: ${net_profit_usd:,.0f} — {'PROFITABLE' if profitable else 'UNPROFITABLE'}."
        ),
    }


def quick_sanity_check(
    finding_severity: str,
    protocol_tvl_usd: float,
    chain: str = "ethereum",
    gas_price_gwei: float = 30.0,
) -> dict:
    """
    Fast economics sanity check given a finding severity and protocol TVL.

    Uses conservative extraction fractions:
      CRIT → 30% of TVL, HIGH → 10%, MED → 3%, LOW → 0.5%

    Useful when a finding has no specific cost estimate yet.
    """
    fraction = {"CRIT": 0.30, "HIGH": 0.10, "MED": 0.03, "LOW": 0.005}.get(
        finding_severity, 0.05
    )
    gas_by_chain = {
        "ethereum": 500_000,
        "solana":   10_000,
        "sui":      50_000,
        "bitcoin":  0,
    }
    return calculate_attack_cost(
        extractable_value_usd=protocol_tvl_usd * fraction,
        gas_estimate_units=gas_by_chain.get(chain, 500_000),
        gas_price_gwei=gas_price_gwei,
    )
