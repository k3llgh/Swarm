"""
nano_swarm/re_nano/seed_ingestion.py
─────────────────────────────────────
Loads exploit_seeds.json and groups seeds into pattern clusters.

Each cluster becomes one AbstractPattern in Phase 1.
Related vulnerability classes (e.g. all reentrancy variants) are merged
into one bucket so the pattern extractor sees the full picture and can
generalise across ETH CEI violations, Solana CPI reentrancy, and Sui
return-vs-abort together — or separately per chain when they're distinct.

Merging logic:
  - Keys are vulnerability class strings, slugified and looked up in VULN_ALIASES
  - Seeds on the same chain with the same canonical class → one bucket
  - Multi-chain seeds are resolved to their primary chain(s)
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Iterator

from .schemas import ExploitSeed

# ── Chain fidelity modifiers ─────────────────────────────────────────────────
# Applied to sandbox training weights: Ethereum mainnet fork is highest fidelity.
CHAIN_FIDELITY: dict[str, float] = {
    "ethereum": 1.00,
    "solana":   0.90,
    "sui":      0.85,
    "bitcoin":  0.70,   # regtest is limited; description-only for most seeds
    "multi":    0.90,   # resolved to primary chain below
}

# Multi-chain exploits mapped to the chain(s) where the vulnerability lives
_MULTI_CHAIN_MAP: dict[str, list[str]] = {
    "Nomad Bridge":                 ["ethereum"],
    "Ronin Bridge (Axie Infinity)": ["ethereum"],
    "Poly Network":                 ["ethereum"],
    "Optimism":                     ["ethereum"],
    "Multichain (Anyswap)":         ["ethereum"],
}


def _slug(text: str) -> str:
    """Convert a vulnerability class string to a lowercase slug for dict lookup."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")[:40]


# ── Canonical vulnerability class aliases ────────────────────────────────────
# Maps slugified seed vulnerability_class values to canonical bucket names.
# Build at module load time so the lookup cost is O(1) per seed.

_RAW_ALIASES: dict[str, str] = {
    # Reentrancy family (Ethereum + Solana CPI + Sui return-vs-abort)
    "deferred-health-check / CEI-violation":                     "reentrancy",
    "reentrancy / CEI-violation":                                "reentrancy",
    "cross-function / reentrancy / ETH-callback":                "reentrancy",
    "reentrancy / cross-function / ETH-callback":                "reentrancy",
    "concentrated-liquidity-tick / reentrancy":                  "reentrancy",
    "non-standard-erc / erc777-reentrancy":                      "reentrancy",
    "non-standard-erc / erc677-cross-function-reentrancy":       "reentrancy",
    "same-asset-liquidation / reentrancy":                       "reentrancy",
    "msg-value-reuse / value-accounting":                        "reentrancy",
    "return-vs-abort / state-commit-on-error":                   "return-vs-abort",   # Sui-specific

    # Access control family (Ethereum upgrades + Solana 6-step + Sui capability)
    "missing-signer-check / arbitrary-CPI":                      "access-control",
    "missing-ownership-check / fabricated-account":              "access-control",
    "missing-signer-check / authority-bypass":                   "access-control",
    "non-canonical-PDA / shadow-account":                        "access-control",
    "stale-data-after-CPI / stale-cache":                        "access-control",
    "reinitialization / account-revival":                        "access-control",
    "type-cosplay / discriminator-bypass":                       "access-control",
    "duplicate-mutable-account / aliasing":                      "access-control",
    "arbitrary-CPI / program-ID-substitution":                   "access-control",
    "trusted-zero / unvalidated-merkle-root":                    "access-control",
    "initialiser-front-run / missing-disableInitializers":       "access-control",
    "role-escalation / unguarded-upgrade-path":                  "access-control",
    "arbitrary-calldata / cross-chain-privilege-escalation":     "access-control",
    "arbitrary-calldata / missing-approval-check":               "access-control",
    "validator-key-compromise / role-centralisation":            "access-control",
    "key-centralisation / tainted-trust":                        "access-control",
    "delegatecall-to-user-controlled / unprotected-library":     "access-control",
    "visibility-bypass / public-package-entry":                  "access-control",
    "caller-param-spoofing / authority-bypass":                  "access-control",
    "phantom-type / role-escalation":                            "access-control",
    "UID-type-swap / on-chain-type-change":                      "access-control",
    "object-capability / key-store-free-transfer":               "access-control",
    "ctx.sender()-confusion / privilege-transfer":               "access-control",
    "weak-key-generation / no-two-step-rotation":                "access-control",

    # Governance
    "proposal-dependency / governance-composition":              "governance",
    "governance-flash-loan / snapshot-timing":                   "governance",
    "flash-loan-governance / snapshot-timing":                   "governance",
    "proposal-dependency / emergency-pause-bypass":              "governance",

    # Bitcoin coinbase / slashing
    "coinbase-maturity-bypass / slashing-window":                "bitcoin-coinbase",
    "null-prevout / coinbase-parser":                            "bitcoin-coinbase",
    "coinbase-maturity / bridge-deposit":                        "bitcoin-coinbase",
    "script-type-assumption / slashing-invalid":                 "bitcoin-coinbase",

    # Bitcoin operational
    "checkpoint-relay / rpc-error-handling":                     "bitcoin-operational",
    "fee-refund / granter-vs-payer":                             "bitcoin-operational",
    "state-machine / underflow-panic":                           "bitcoin-operational",

    # Oracle
    "self-referential-oracle / price-manipulation":              "oracle",
    "stale-oracle / missing-staleness-check":                    "oracle",
    "self-referential-oracle / flash-loan-price":                "oracle",
    "self-referential-oracle / low-liquidity-TWAP":              "oracle",
    "TWAP-bypass / spot-price-oracle":                           "oracle",
    "read-only-reentrancy":                                      "oracle",

    # Move verifier / arithmetic
    "verifier-bypass / CFG-construction-bug":                    "move-verifier",
    "bitwise-overflow / silent-truncation":                      "move-arithmetic",

    # Arithmetic / precision
    "precision-cliff / reward-lock":                             "arithmetic-precision",
    "unchecked-arithmetic / silent-wrap":                        "arithmetic-precision",
    "unchecked-arithmetic / unlimited-mint":                     "arithmetic-precision",
    "interest-rate-overflow / arithmetic-boundary":              "arithmetic-precision",
    "precision-cliff / share-inflation-rounding":                "arithmetic-precision",

    # AMM / vault invariants
    "constant-product-invariant / arithmetic-precision":         "amm-invariant",
    "price-limit-boundary / tick-arithmetic":                    "amm-invariant",
    "share-inflation / donation-attack":                         "vault-invariant",

    # Protocol-level
    "composability-assumption / pending-vs-completed":           "composability",
    "storage-collision / proxy-pattern":                         "storage-layout",
    "storage-layout / upgrade-collision":                        "storage-layout",
    "storage-gap / upgrade-collision":                           "storage-layout",
    "transient-storage-slot-collision":                          "storage-layout",
    "ABI-selector-collision / proxy-dispatch":                   "storage-layout",
    "rebasing-token / snapshot-mismatch":                        "token-accounting",
    "fee-on-transfer / amount-vs-balance":                       "token-accounting",
    "trapped-value / no-exit-path":                              "value-conservation",
    "whitepaper-formula-divergence / price-inversion":           "spec-divergence",
    "parameter-validation / formula-invariant":                  "spec-divergence",
    "slippage-not-enforced-on-chain / flash-loan-oracle":        "mev-slippage",
    "PTB-command-limit / iteration-DoS":                         "move-dos",
    "duplicate-key / user-DoS":                                  "move-dos",
    "logic-boundary / off-by-one":                               "boundary-condition",
}

# Build slugged lookup once at module load
VULN_ALIASES: dict[str, str] = {_slug(k): v for k, v in _RAW_ALIASES.items()}


# ── Public interface ──────────────────────────────────────────────────────────

def load_seeds(path: str | Path) -> list[ExploitSeed]:
    """Load and validate exploit_seeds.json."""
    with open(path) as fh:
        data = json.load(fh)
    return [ExploitSeed(**raw) for raw in data["exploits"]]


def group_seeds(seeds: list[ExploitSeed]) -> dict[str, list[ExploitSeed]]:
    """
    Group seeds into pattern buckets keyed by "{chain}::{canonical_class}".
    Seeds in the same bucket will be merged into one AbstractPattern.
    """
    buckets: dict[str, list[ExploitSeed]] = defaultdict(list)

    for seed in seeds:
        chains = _resolve_chains(seed)
        canonical = VULN_ALIASES.get(_slug(seed.vulnerability_class), _slug(seed.vulnerability_class))

        for chain in chains:
            buckets[f"{chain}::{canonical}"].append(seed)

    return dict(buckets)


def iter_groups(seeds: list[ExploitSeed]) -> Iterator[tuple[str, str, list[ExploitSeed]]]:
    """
    Yield (chain, canonical_vuln_class, seeds) for each pattern bucket.
    Primary interface for the Phase 1 pattern extractor.
    """
    for key, group in sorted(group_seeds(seeds).items()):
        chain, vuln_class = key.split("::", 1)
        yield chain, vuln_class, group


def build_pattern_id(chain: str, vuln_class: str, seq: int) -> str:
    """
    Build a human-readable pattern ID.
    Example: "ETH-REENTRANCY-003", "SOL-ACCESS_CONTROL-002"
    """
    prefixes = {"ethereum": "ETH", "solana": "SOL", "sui": "SUI", "bitcoin": "BTC"}
    prefix = prefixes.get(chain, chain[:3].upper())
    slug = vuln_class.upper().replace("-", "_")[:20]
    return f"{prefix}-{slug}-{seq:03d}"


def summarise(seeds: list[ExploitSeed]) -> None:
    """Print a human-readable ingestion summary to stdout."""
    from rich.console import Console
    from rich.table import Table

    groups = group_seeds(seeds)
    console = Console()
    console.print(f"\n[bold]Seed Ingestion Summary[/bold]")
    console.print(f"  Raw seeds:      {len(seeds)}")
    console.print(f"  Pattern groups: {len(groups)} (after merging related classes)\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Chain",  style="dim", width=10)
    table.add_column("Vulnerability Class", width=38)
    table.add_column("Seeds", justify="right", width=6)
    table.add_column("Confirmed Loss",  justify="right", width=16)

    for key, group in sorted(groups.items()):
        chain, vuln = key.split("::", 1)
        loss = sum(s.loss_amount_usd for s in group if s.loss_amount_usd)
        table.add_row(
            chain,
            vuln,
            str(len(group)),
            f"${loss:,}" if loss else "—",
        )

    console.print(table)


# ── Private helpers ───────────────────────────────────────────────────────────

def _resolve_chains(seed: ExploitSeed) -> list[str]:
    """Return the effective chain(s) for a seed. Multi-chain seeds are mapped."""
    if seed.chain != "multi":
        return [seed.chain]
    return _MULTI_CHAIN_MAP.get(seed.affected_protocol, ["ethereum"])
