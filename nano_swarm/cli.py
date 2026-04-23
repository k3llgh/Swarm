"""
nano_swarm/cli.py
──────────────────
Command-line interface for the Nano Swarm auditing system.

Commands:
  audit     — audit a single contract file
  pipeline  — run the RE Nano curriculum generation pipeline
  stats     — show curriculum and pitfall statistics
  loop3     — show Loop 3 PoC attempt trend
  ingest    — show seed ingestion summary (no API calls)
  validate  — validate .env configuration
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.logging import RichHandler

app = typer.Typer(
    name="swarm",
    help="Nano Swarm — self-educating blockchain security auditing system",
    add_completion=False,
)
console = Console()


def _setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, markup=True)],
    )


# ── audit ─────────────────────────────────────────────────────────────────────

@app.command()
def audit(
    contract: Path = typer.Argument(..., help="Path to contract source file"),
    chain: str     = typer.Option("ethereum", "--chain", "-c",
                                  help="ethereum | solana | sui | bitcoin"),
    name: str      = typer.Option("", "--name", "-n", help="Protocol name (for report)"),
    tvl: Optional[float] = typer.Option(None, "--tvl", help="Protocol TVL in USD (enables cost accounting)"),
    gas: float     = typer.Option(30.0, "--gas", help="Gas price in gwei (Ethereum)"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write report JSON here"),
    debug: bool    = typer.Option(False, "--debug", help="Verbose logging"),
) -> None:
    """Audit a single smart contract source file."""
    _setup_logging(debug)
    _check_config()

    if not contract.exists():
        console.print(f"[red]File not found: {contract}[/red]")
        raise typer.Exit(1)

    from .pipeline.orchestrator import AuditInput, PipelineOrchestrator

    orch = PipelineOrchestrator()
    inp  = AuditInput(
        contract_code=contract.read_text(),
        chain=chain,
        protocol_name=name or contract.stem,
        tvl_usd=tvl,
        gas_price_gwei=gas,
    )

    report = orch.audit(inp)
    console.print(report.summary())

    if out:
        report.save(out)
        console.print(f"[green]Report saved → {out}[/green]")


# ── pipeline ──────────────────────────────────────────────────────────────────

@app.command()
def pipeline(
    seeds: Optional[Path] = typer.Option(None, "--seeds", "-s",
                                          help="Path to exploit_seeds.json"),
    max_patterns: Optional[int]  = typer.Option(None, "--max-patterns", "-m",
                                                 help="Stop after N patterns (pilot mode)"),
    variations: Optional[int]    = typer.Option(None, "--variations", "-v",
                                                 help="Code examples per pattern"),
    no_sandbox: bool             = typer.Option(False, "--no-sandbox",
                                                help="Skip PoC execution (faster, no Foundry needed)"),
    no_cache: bool               = typer.Option(False, "--no-cache",
                                                help="Re-extract patterns even if cached"),
    debug: bool                  = typer.Option(False, "--debug"),
) -> None:
    """
    Run the RE Nano curriculum generation pipeline.

    Generates sandbox-validated training examples for specialist nanos.
    Uses the seed file specified by SEEDS_PATH in .env if --seeds is not given.
    """
    _setup_logging(debug)
    _check_config()

    from .config import settings
    from .re_nano.orchestrator import RENano

    seeds_path = seeds or settings.seeds_path
    if not seeds_path.exists():
        console.print(f"[red]Seeds file not found: {seeds_path}[/red]")
        console.print("Run with --seeds path/to/exploit_seeds.json")
        raise typer.Exit(1)

    # Override seeds path for this run
    settings.__dict__["_seeds_override"] = seeds_path

    if no_cache:
        cache = settings.patterns_dir / "patterns.json"
        if cache.exists():
            cache.unlink()
            console.print("[yellow]Pattern cache cleared[/yellow]")

    re = RENano()
    result = re.run(
        max_patterns=max_patterns,
        variations_per_pattern=variations,
        skip_sandbox=no_sandbox,
    )

    console.print(f"\n[green]Pipeline complete.[/green]")
    console.print(f"  Patterns extracted : {result['patterns']}")
    console.print(f"  Curriculum items   : {result['curriculum_stats']['total_items']}")
    console.print(f"  Sandbox confirmed  : {result['curriculum_stats']['sandbox_confirmed']}")
    console.print(f"  Duration           : {result['elapsed_seconds']}s")


# ── stats ─────────────────────────────────────────────────────────────────────

@app.command()
def stats(debug: bool = typer.Option(False, "--debug")) -> None:
    """Print curriculum store and pitfall log statistics."""
    _setup_logging(debug)

    from .re_nano.curriculum import curriculum_stats
    from .re_nano.self_education import pitfall_stats

    cs = curriculum_stats()
    ps = pitfall_stats()

    console.print("\n[bold cyan]Curriculum Store[/bold cyan]")
    console.print(f"  Total items        : {cs['total_items']}")
    console.print(f"  Sandbox confirmed  : {cs['sandbox_confirmed']}")
    console.print(f"  Training weight    : {cs['total_training_weight']:.1f}")
    console.print(f"  By chain           : {cs['by_chain']}")
    console.print(f"  By label           : {cs['by_label']}")
    if cs["lora_ready_patterns"]:
        console.print(f"\n  [bold]LoRA-ready patterns[/bold] (≥{50} confirmed examples):")
        for p in cs["lora_ready_patterns"]:
            console.print(f"    {p['pattern_id']:<35} {p['confirmed_count']} examples")

    console.print("\n[bold cyan]Pitfall Log[/bold cyan]")
    console.print(f"  Total entries      : {ps['total_entries']}")
    console.print(f"  Resolved rate      : {ps['resolved_rate']:.0%}")
    console.print(f"  LoRA transition    : {'[yellow]RECOMMENDED[/yellow]' if ps['lora_transition_recommended'] else 'not yet'}")
    console.print(f"  By type            : {ps['by_type']}")


# ── loop3 ─────────────────────────────────────────────────────────────────────

@app.command()
def loop3(debug: bool = typer.Option(False, "--debug")) -> None:
    """
    Show Loop 3 health metric: average PoC attempts per pattern.
    A decreasing trend means the RE Nano is learning from its mistakes.
    """
    _setup_logging(debug)

    from .re_nano.self_education import attempts_trend

    trend = attempts_trend()
    if not trend:
        console.print("[yellow]No Loop 3 data yet. Run 'swarm pipeline' first.[/yellow]")
        raise typer.Exit(0)

    console.print("\n[bold cyan]Loop 3 — PoC Attempts Per Pattern[/bold cyan]")
    console.print("(Lower average = RE Nano is learning)\n")
    for pid, avg in sorted(trend.items(), key=lambda x: x[1]):
        bar = "█" * max(1, int(avg * 5))
        console.print(f"  {pid:<38} {bar} {avg:.2f}")


# ── ingest ────────────────────────────────────────────────────────────────────

@app.command()
def ingest(
    seeds: Optional[Path] = typer.Option(None, "--seeds", "-s",
                                          help="Path to exploit_seeds.json"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Show seed ingestion summary without making any API calls."""
    _setup_logging(debug)

    from .config import settings
    from .re_nano.seed_ingestion import load_seeds, summarise

    seeds_path = seeds or settings.seeds_path
    if not seeds_path.exists():
        console.print(f"[red]Seeds file not found: {seeds_path}[/red]")
        raise typer.Exit(1)

    loaded = load_seeds(seeds_path)
    summarise(loaded)


# ── validate ──────────────────────────────────────────────────────────────────

@app.command()
def validate(debug: bool = typer.Option(False, "--debug")) -> None:
    """Validate .env configuration and check tool availability."""
    _setup_logging(debug)

    from .config import settings
    from .re_nano.sandbox_validator import TOOL_AVAILABLE

    problems = settings.validate()

    console.print("\n[bold cyan]Configuration[/bold cyan]")
    console.print(f"  LLM backend   : {settings.llm_backend}")
    console.print(f"  Data dir      : {settings.data_dir}")
    console.print(f"  Seeds path    : {settings.seeds_path}")
    console.print(f"  Variations    : {settings.variations_per_pattern} per pattern")

    console.print("\n[bold cyan]Sandbox tools[/bold cyan]")
    for tool, available in TOOL_AVAILABLE.items():
        status = "[green]✓[/green]" if available else "[red]✗ not found[/red]"
        console.print(f"  {tool:<10} {status}")

    if problems:
        console.print("\n[bold red]Configuration problems:[/bold red]")
        for p in problems:
            console.print(f"  [red]✗[/red] {p}")
        raise typer.Exit(1)
    else:
        console.print("\n[green]Configuration OK[/green]")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_config() -> None:
    """Exit early with a helpful message if configuration is invalid."""
    from .config import settings
    problems = settings.validate()
    if problems:
        for p in problems:
            console.print(f"[red]Config error: {p}[/red]")
        console.print("Copy .env.example → .env and fill in your API keys.")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
