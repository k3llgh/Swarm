# Nano Swarm — Self-Educating Blockchain Security Auditing System

A modular, multi-agent auditing pipeline that teaches itself from every audit it runs.
Each mistake becomes training data. Each confirmed exploit becomes a weapon against the next one.

---

## Architecture

```
SEED MATERIAL (77 real exploits — $3.38B confirmed losses)
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  RE & TEACHING NANO                                     │
│  Phase 1: extract abstract pattern from seed group      │
│  Phase 2: generate diverse code examples (embedded)     │
│  Phase 3: validate via sandbox (compiler = oracle)      │
│  Phase 4: package curriculum items                      │
│  Phase 5: inject as few-shot context at audit time      │
└─────────────────────────────────────────────────────────┘
         │  curriculum
         ▼
  Code Reader  →  Architecture Synthesizer
                           │ routing plan
                    ┌──────┴──────┐
                    ▼             ▼
           Reentrancy Master   Access Control Specialist
           (ETH/SOL/SUI)       (all 4 chains)
                    │             │
                    └──────┬──────┘
                           │ findings + lateral signals
                           ▼
                    Cost Accounting (Python)
                           │
                    Triage Nano  (EG→UP→US→CP→DI)
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
           ACCEPT      REJECT        JURY
           (output)  (Loop 1)   (prosecution→defense→verdict)
                                       │
                                 CONFIRMED / REJECTED / DOWNGRADED / HUMAN
```

### The three trust principles

| Principle | Constraint |
|---|---|
| **Nano Trust Minimisation** | No nano output consumed by another nano directly — everything passes through the orchestrator |
| **Human Trust Maximisation** | Three triggers always route to a human queue (H-1: severity delta > 1 level; H-2: novel pattern; H-3: jury uncertain) |
| **Code Trust Maximisation** | Nano confidence scores determine routing only — sandbox execution is the final arbiter for CRIT findings |

### The three learning loops

| Loop | Signal | Effect |
|---|---|---|
| **Loop 1** | Triage rejects a specialist nano finding | RE Nano generates adversarial examples targeting that mistake class |
| **Loop 2** | Jury overturns a triage decision | RE Nano generates triage correction examples; triage LoRA updates monthly |
| **Loop 3** | RE Nano PoC fails sandbox | RE Nano logs the fault, revises approach, reduces `attempts_per_pattern` over time |

---

## Quick Start

### 1. Prerequisites

```bash
# Python 3.11+
pip install -r requirements.txt

# Ethereum sandbox (optional but recommended)
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Local LLM via Ollama (alternative to DeepSeek/Anthropic API)
# https://ollama.ai — then: ollama pull deepseek-r1:7b
```

### 2. Configuration

```bash
cp .env.example .env
# Edit .env — set at minimum:
#   LLM_BACKEND=deepseek   (or anthropic / ollama)
#   DEEPSEEK_API_KEY=sk-...
```

### 3. Validate configuration

```bash
python -m nano_swarm.cli validate
```

### 4. Inspect the seed material

```bash
python -m nano_swarm.cli ingest --seeds seeds/exploit_seeds.json
```

### 5. Run the curriculum generation pipeline (pilot: 3 patterns, 10 examples each)

```bash
python -m nano_swarm.cli pipeline \
  --seeds seeds/exploit_seeds.json \
  --max-patterns 3 \
  --variations 10
```

### 6. Audit a contract

```bash
python -m nano_swarm.cli audit MyContract.sol \
  --chain ethereum \
  --name MyProtocol \
  --tvl 5000000 \
  --out reports/my_protocol.json
```

### 7. Run tests (no API key required)

```bash
pytest tests/ -v
# or
python tests/test_pipeline.py
```

---

## Docker

```bash
# Build
docker compose build

# Run with DeepSeek API
docker compose run swarm pipeline --seeds seeds/exploit_seeds.json

# Run with local Ollama (includes the Ollama sidecar)
docker compose --profile ollama up -d
docker compose run swarm pipeline --seeds seeds/exploit_seeds.json

# Run with Ethereum sandbox
docker compose --profile sandbox up -d
```

---

## Project Structure

```
nano_swarm/
├── config.py                    # All settings (loaded from .env)
├── llm_client.py                # Unified LLM client: DeepSeek / Anthropic / Ollama
├── cli.py                       # Typer CLI: audit | pipeline | stats | loop3 | ingest | validate
│
├── re_nano/
│   ├── schemas.py               # All data contracts (Pydantic)
│   ├── seed_ingestion.py        # Load seeds → 26 pattern groups
│   ├── pattern_extractor.py     # Phase 1: abstract pattern from seed group
│   ├── variation_generator.py   # Phase 2: diverse examples + embedding diversity
│   ├── sandbox_validator.py     # Phase 3: PoC execution + fault diagnosis
│   ├── curriculum.py            # Phase 4+5: package + teach specialist nanos
│   ├── self_education.py        # Loop 3: pitfall log, build_pitfall_context
│   └── orchestrator.py          # Pipeline wiring + Loop 1/2 signal receivers
│
├── specialist_nanos/
│   ├── base.py                  # BaseSpecialistNano, Finding, NanoResult, LateralSignal
│   ├── reentrancy_master.py     # ETH/SOL/SUI reentrancy (8 classes)
│   └── access_control.py        # All 4 chains, Frank Castle 6-step (Solana)
│
├── triage/
│   ├── nano.py                  # Five-step triage (EG→UP→US→CP→DI)
│   └── invalidation_library.py  # Full invalidation library as Python constant
│
├── jury/
│   └── orchestrator.py          # Adversarial debate: prosecution→defense→verdict
│
├── tools/
│   └── cost_accounting.py       # Deterministic attack economics (not an LLM)
│
└── pipeline/
    └── orchestrator.py          # Main audit pipeline + report generation

seeds/
├── exploit_seeds.json           # 77 real-world exploits ($3.38B losses)
└── exploit_seed_compiler.py     # Script to regenerate exploit_seeds.json

tests/
└── test_pipeline.py             # 8 tests, no API key required
```

---

## Seed Material

77 real-world exploits mapped to checklist rows across four chains.

| Chain | Patterns | Seeds | Notable exploits |
|---|---|---|---|
| Ethereum | 15 | 41 | Euler $197M, Nomad $190M, Ronin $625M, Curve $73M |
| Solana | 3 | 12 | Cashio $48M, Wormhole $320M, Mango $116M |
| Sui Move | 6 | 12 | Zellic CFG bug, Panther return-vs-abort, Monethic labs |
| Bitcoin | 2 | 7 | Babylon M-1, Stacks sBTC null prevout |
| Multi | — | 5 | Poly Network $611M, Ronin, Multichain |

---

## Adding a New Specialist Nano

```python
# nano_swarm/specialist_nanos/oracle_specialist.py
from .base import BaseSpecialistNano, Finding, NanoResult

class OracleSpecialistNano(BaseSpecialistNano):
    NANO_NAME = "OracleSpecialist"
    VULNERABILITY_CLASSES = ["stale-oracle", "self-referential-oracle", "twap-manipulation"]
    SUPPORTED_CHAINS = ["ethereum", "solana"]

    def _build_system_prompt(self, chain: str) -> str:
        return ORACLE_SYSTEM_PROMPT + CHAIN_ADDENDUM[chain]

    def _parse_response(self, raw_text: str, result: NanoResult, chain: str) -> NanoResult:
        for raw in self._extract_json(raw_text):
            result.add_finding(Finding(nano=self.NANO_NAME, ...))
        return result
```

Then register it in `nano_swarm/pipeline/orchestrator.py`:

```python
self.nanos = [
    ReentrancyMasterNano(),
    AccessControlSpecialistNano(),
    OracleSpecialistNano(),      # ← add here
]
```

---

## Validation Gate (Learning Loops)

Both Loop 1 and Loop 2 apply a dual-metric validation gate before deploying any LoRA update.
A model that learns to reject everything achieves 0% FP but also 0% TP.

```python
def validate_update(candidate, validation_set):
    old_fp, old_tp = evaluate(current_model, validation_set)
    new_fp, new_tp = evaluate(candidate, validation_set)

    fp_improved = new_fp <= old_fp
    tp_held     = new_tp >= (old_tp * 0.95)   # max 5% TP regression

    return candidate if (fp_improved and tp_held) else current_model
```

---

## Success Metrics

| Metric | Target |
|---|---|
| TP rate vs human baseline | > 70% of known findings |
| FP rate post-triage | < 20% of raw nano output |
| Sandbox confirmation rate (CRIT) | > 60% of CRIT findings pass PoC |
| Triage accuracy | > 85% agreement with jury |
| Jury overturn rate | < 15% of triage decisions |
| Human escalation rate | 2–5% of all findings |
| Loop 3 trend | `attempts_per_pattern` decreasing over 90 days |

Human escalation rate at 0% means the system is suppressing novel findings.
Human escalation rate > 5% means RE Nano curriculum is drifting outside coverage.
**2–5% is the healthy range.**
