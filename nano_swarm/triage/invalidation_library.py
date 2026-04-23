"""
nano_swarm/triage/invalidation_library.py
──────────────────────────────────────────
The invalidation library as a Python constant.

This is the same library defined in invalidation-library.md, converted
to a string constant so it can be injected directly into the Triage Nano's
system prompt at runtime without reading from disk.

Keeping it in Python means it is version-controlled alongside the code and
visible to the IDE type-checker. The triage nano reads this on every call —
no caching, no drift from the on-disk version.
"""

INVALIDATION_LIBRARY = """
## INVALIDATION LIBRARY

### STEP 1 — EXISTING GUARD (EG)

EG-1: Access control prevents the described caller
  The vulnerable function has an access modifier or equivalent check that
  prevents the attacker described in the finding from calling it.

EG-2: Reentrancy guard blocks the described path
  The contract uses nonReentrant, a lock modifier, or a correct
  checks-effects-interactions ordering that prevents the reentrant call.

EG-3: Minimum amount or threshold check blocks dust attacks
  A minimum deposit, withdrawal, or transfer amount prevents the
  dust-amount manipulation described in the finding.

EG-4: Pause mechanism provides emergency mitigation
  The protocol can be paused by governance before significant damage occurs.
  This bounds the exploitable window even if it doesn't fix the root cause.

EG-5: Input validation check prevents the attack vector
  The function validates its inputs (non-zero address, bounded range, valid
  enum) in a way that blocks the specific input the attack requires.

### STEP 2 — UNREALISTIC PRECONDITIONS (UP)

UP-1: Requires extreme token decimals
  The attack only works with tokens using non-standard decimals (>24 or 0).
  Most real tokens use 6 or 18 decimals.

UP-2: Requires attacker to hold majority of token supply
  Acquiring >50% of a meaningful token's supply would be prohibitively
  expensive and would itself move the price against the attacker.

UP-3: Requires specific block.timestamp or block.number
  Exact timestamp targeting is impractical without validator collusion
  (~15 second drift on Ethereum).

UP-4: Requires unrealistic initial deposit or position size
  The attack needs more capital than exists in the protocol or related markets.

UP-5: Requires multiple low-probability events to coincide
  The combined probability of all required conditions makes the attack
  practically infeasible even if each condition alone is possible.

### STEP 3 — UNREACHABLE STATE (US)

US-1: Required state combination prevented by invariant
  The protocol maintains an invariant that makes the required combination
  of state values impossible — other functions prevent it.

US-2: Previous operation always resets the vulnerable variable
  The vulnerable state depends on leftover data from a prior operation, but
  that operation always resets or clears the variable before returning.

US-3: Initialisation prevents the zero-state attack
  The constructor or initialiser always sets state to a safe non-zero value
  before any user interaction is possible.

US-4: Sequence of operations blocked by intermediate check
  An intermediate step in the required attack sequence has a check that
  fails given the state produced by the preceding step.

### STEP 4 — COST EXCEEDS PROFIT (CP)

CP-1: Gas cost exceeds extractable value
  The cumulative gas cost of the attack transactions exceeds the maximum
  extractable value. Use the cost_accounting numbers — do not estimate.

CP-2: Flash loan fees make the attack unprofitable
  Flash loan fees on the required borrow amount exceed the profit.
  Typical rates: Aave 0.09%, Uniswap V3 0.05%.

CP-3: Slippage on required swaps exceeds profit
  Large swaps needed for the attack incur slippage that eliminates the margin.

CP-4: Capital lockup opportunity cost exceeds grief value
  The attacker must lock capital for long enough that the opportunity cost
  outweighs the damage inflicted.

CP-5: Sustained multi-block spend grows while extractable value does not
  The cost of the attack accumulates across many blocks while the maximum
  extractable value stays fixed or decreases.

### STEP 5 — IMPACT (DI / SH / IM)

DI-1: Rounding error bounded to 1 wei per operation
  The maximum discrepancy per operation is 1 wei (or smallest unit).
  This does not compound meaningfully even over millions of operations.

DI-2: Impact does not compound across operations
  Each operation independently rounds. Errors are absorbed or corrected
  by subsequent operations — no accumulation mechanism exists.

DI-3: Loss below minimum transferable or withdrawable amount
  The theoretical loss is smaller than the protocol's minimum operation
  size — affected users cannot realise it.

DI-4: Precision loss within acceptable tolerance
  The precision loss is within the standard tolerance for DeFi (<0.01%).
  Financial protocols inherently have rounding; this level is expected.

SH-1: Attacker can only reduce their own balance
  The manipulation only affects the attacker's own position. Self-inflicted
  losses are not a valid security finding.

SH-2: Grief requires permanently locking own funds
  To execute the grief, the attacker must sacrifice funds equal to or
  greater than the damage caused — economically irrational.

SH-3: Attack outcome is equivalent to a donation
  The net effect is that the attacker transfers value to other users or
  the protocol without receiving anything. Functionally a donation.

IM-1: Profit calculation ignores fees
  The claimed profit/loss omits gas, protocol fees, swap fees, or flash
  loan fees that significantly reduce or eliminate the impact.

IM-2: Assumes linear scaling but function is capped
  The report extrapolates linearly but the function has a cap or diminishing
  returns that bound the maximum impact well below the claim.

IM-3: Uses wrong decimal or precision in calculation
  The PoC or impact calculation uses incorrect decimal places or unit
  conversion, producing inflated numbers.

IM-4: Conflates theoretical maximum with realistic impact
  The report presents the absolute worst-case as expected impact. Under
  any realistic market conditions the actual impact is orders of magnitude
  smaller.

### ALREADY MITIGATED (AM)

AM-1: A separate function resets the vulnerable state
  A periodic settlement, rebalance, or sync call resets the state the
  attack depends on. The vulnerable state is transient and self-correcting.

AM-2: Timelock or governance delay allows defensive response
  The attack requires a parameter change, but the timelock gives monitoring
  systems enough time to detect and counter it.

AM-3: Circuit breaker or rate limit bounds maximum damage
  The protocol has a per-transaction cap or rate limiter that bounds
  extractable value per period. The finding ignores these limits.

AM-4: Monitoring and emergency pause can halt the attack
  Active monitoring with pause capability significantly reduces the
  practical exploit window.

### OUT OF SCOPE (OS)

OS-1: Affected code is in a test or mock file only
  The vulnerable code is never deployed to production.

OS-2: Vulnerability is in an external dependency
  The issue is in a third-party contract or library that the protocol does
  not control. The protocol uses the dependency correctly.

OS-3: Code path unreachable from any deployed entry point
  The vulnerable function is internal and never called by any public function.

OS-4: Finding applies to a deprecated component
  The affected contract or function is being phased out; no user funds flow
  through this code path.
"""
