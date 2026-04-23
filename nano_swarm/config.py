"""
nano_swarm/config.py
────────────────────
Single source of truth for all runtime settings.
Values come from environment variables (loaded from .env by dotenv).

Usage:
    from nano_swarm.config import settings
    print(settings.llm_backend)
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the project root (parent of nano_swarm/)
load_dotenv(Path(__file__).parent.parent / ".env")


class Settings:
    """
    Immutable settings container. All fields have safe defaults so the
    system can at least start without a fully-populated .env file.
    """

    # ── LLM backend ──────────────────────────────────────────────────────────
    @property
    def llm_backend(self) -> str:
        """deepseek | anthropic | ollama"""
        return os.getenv("LLM_BACKEND", "deepseek").lower()

    @property
    def deepseek_api_key(self) -> str:
        return os.getenv("DEEPSEEK_API_KEY", "")

    @property
    def deepseek_model(self) -> str:
        return os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    @property
    def deepseek_api_base(self) -> str:
        return os.getenv("DEEPSEEK_API_BASE", "https://api.deepseek.com/v1")

    @property
    def anthropic_api_key(self) -> str:
        return os.getenv("ANTHROPIC_API_KEY", "")

    @property
    def anthropic_model(self) -> str:
        return os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

    @property
    def ollama_host(self) -> str:
        return os.getenv("OLLAMA_HOST", "http://localhost:11434")

    @property
    def ollama_model(self) -> str:
        return os.getenv("OLLAMA_MODEL", "deepseek-r1:7b")

    # ── Sandbox ───────────────────────────────────────────────────────────────
    @property
    def eth_rpc_url(self) -> str:
        return os.getenv("ETH_RPC_URL", "")

    @property
    def eth_fork_block(self) -> str:
        return os.getenv("ETH_FORK_BLOCK", "latest")

    # ── Data paths ────────────────────────────────────────────────────────────
    @property
    def data_dir(self) -> Path:
        return Path(os.getenv("DATA_DIR", "./data"))

    @property
    def seeds_path(self) -> Path:
        return Path(os.getenv("SEEDS_PATH", "./seeds/exploit_seeds.json"))

    @property
    def curriculum_dir(self) -> Path:
        return self.data_dir / "curriculum"

    @property
    def patterns_dir(self) -> Path:
        return self.data_dir / "patterns"

    @property
    def pitfall_dir(self) -> Path:
        return self.data_dir / "pitfall_logs"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    # ── Pipeline tuning ───────────────────────────────────────────────────────
    @property
    def variations_per_pattern(self) -> int:
        return int(os.getenv("VARIATIONS_PER_PATTERN", "30"))

    @property
    def diversity_threshold(self) -> float:
        return float(os.getenv("DIVERSITY_THRESHOLD", "0.25"))

    @property
    def triage_confidence_floor(self) -> float:
        return float(os.getenv("TRIAGE_CONFIDENCE_FLOOR", "0.75"))

    @property
    def crit_jury_threshold(self) -> float:
        return float(os.getenv("CRIT_JURY_THRESHOLD", "0.85"))

    @property
    def lora_batch_min(self) -> int:
        return int(os.getenv("LORA_BATCH_MIN", "50"))

    # ── Logging ───────────────────────────────────────────────────────────────
    @property
    def log_level(self) -> str:
        return os.getenv("LOG_LEVEL", "INFO").upper()

    def validate(self) -> list[str]:
        """
        Return a list of configuration problems. Empty list = config is valid.
        Call at startup to catch missing secrets early.
        """
        problems: list[str] = []

        if self.llm_backend == "deepseek" and not self.deepseek_api_key:
            problems.append("LLM_BACKEND=deepseek but DEEPSEEK_API_KEY is not set")
        if self.llm_backend == "anthropic" and not self.anthropic_api_key:
            problems.append("LLM_BACKEND=anthropic but ANTHROPIC_API_KEY is not set")
        if self.llm_backend not in ("deepseek", "anthropic", "ollama"):
            problems.append(f"Unknown LLM_BACKEND={self.llm_backend!r}")

        return problems

    def ensure_data_dirs(self) -> None:
        """Create data directories if they don't exist."""
        for d in (self.curriculum_dir, self.patterns_dir,
                  self.pitfall_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)


# Module-level singleton — import this everywhere
settings = Settings()
