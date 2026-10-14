# PRD — On-Chain Policy Engine

## 1. Product Overview

### Product name
**On-Chain Policy Engine**

### One-line description
A reusable smart-contract authorization layer that enforces programmable rules before a caller can execute an arbitrary function on an approved target contract.

### Core idea
Think of the Policy Engine as a **firewall for smart-contract calls**.

Instead of hard-coding authorization rules inside every application contract, an administrator can create policies that define:

- Who may call
- Which contract may be called
- Which function may be called
- Maximum ETH/native-token value per call
- Maximum spending within a rolling/fixed daily period
- Minimum cooldown between executions
- Policy expiration
- Whether a policy is active

The engine validates the policy and then executes the target call.

### Primary value
The project should demonstrate strong smart-contract architecture and security engineering rather than being another token, staking, or simple DAO project.

---

# 2. Problem

Smart-contract systems frequently duplicate authorization and spending logic across multiple contracts. This creates several risks:

- Inconsistent authorization rules
- Missing value limits
- Incorrect accounting of spending quotas
- Expired permissions remaining usable
- Replay or nonce mistakes for signed approvals
- Batch-execution edge cases
- Emergency controls that can be bypassed
- Policy updates racing with execution
- Delegate/caller confusion

A reusable policy layer should make these rules explicit, deterministic, auditable, and testable.

---

# 3. Goals

## Must-have goals

1. Create, update, disable, and delete policies.
2. Validate an attempted call against exactly one policy or an explicitly defined policy selection mechanism.
3. Support arbitrary target contracts and function selectors.
4. Enforce per-call native-token value limits.
5. Enforce a spending quota over a configurable accounting period.
6. Enforce cooldowns between successful executions.
7. Enforce policy expiration.
8. Support a global emergency pause.
9. Emit complete events for policy lifecycle and execution decisions.
10. Provide deterministic custom errors for failed policy checks.
11. Provide extensive unit, fuzz, invariant, and malicious-target tests.
12. Keep the core engine generic so other contracts can integrate with it.

## Secondary goals

- Support EIP-712 typed signatures for delegated execution.
- Support batch execution with strict per-call and aggregate limits.
- Provide a read-only simulation/check function.
- Make the system upgradeable only if there is a strong architectural reason; otherwise prefer immutable/non-upgradeable contracts for a smaller attack surface.

---

# 4. Non-Goals

Do **not** turn V1 into a full DAO, treasury, wallet, bridge, or account-abstraction framework.

V1 should not include:

- ERC-20 token implementation
- NFT marketplace
- Lending/borrowing
- Oracle-dependent rules
- Cross-chain messaging
- Governance voting
- Automatic investment strategies
- Off-chain centralized policy servers
- Social recovery
- Upgradeability unless explicitly required

These can be separate future projects.

---

# 5. Target Users / Use Cases

## 5.1 Treasury controller
A treasury can allow an operator to call selected contracts while enforcing a maximum spend per transaction and per accounting period.

Example:

> Operator can call `transfer()` on a specific token contract, up to 1,000 USDC-equivalent token units per execution and 10,000 units per day.

For V1, generic target/value enforcement is mandatory; ERC-20 amount-aware policy enforcement should be treated as an optional extension because decoding arbitrary calldata safely is more complex.

## 5.2 Operations wallet
A team can restrict an operational role to a small set of functions while keeping administrative control separate.

## 5.3 Protocol automation
An automated role can execute predefined functions only during an approved period and subject to quotas.

## 5.4 Smart-contract integration
Another contract can call the Policy Engine rather than implementing its own policy matrix.

---

# 6. Product Principles

1. **Fail closed.** If a policy cannot be proven valid, execution must revert.
2. **Explicit authorization.** Never infer authorization from ambiguous caller relationships.
3. **Deterministic accounting.** Spending and cooldown state must be updated in a predictable order.
4. **No silent bypasses.** Every execution path must pass through the same policy checks.
5. **Minimal privilege.** Policies should grant only the required target/function/value/time permissions.
6. **Security over convenience.** Avoid features that materially increase ambiguity in V1.
7. **Observable behavior.** Important state changes and successful executions must emit events.

---

# 7. Functional Requirements

## 7.1 Policy structure

Use a compact policy model similar to:

```solidity
struct Policy {
    address target;
    bytes4 selector;
    address allowedCaller;
    uint256 maxValue;
    uint256 periodLimit;
    uint64 period;
    uint64 cooldown;
    uint64 validAfter;
    uint64 expiry;
    uint256 spentInPeriod;
    uint64 periodStart;
    uint64 lastExecution;
    bool active;
}
```

The exact storage layout may be improved during implementation, but the semantics must remain explicit.

### Required semantics

- `target == address(0)` is invalid.
- `allowedCaller == address(0)` is invalid unless wildcard callers are explicitly designed and documented.
- `selector` identifies the allowed function.
- `maxValue` limits `msg.value` for a single execution.
- `periodLimit` limits aggregate native-token value over `period`.
- `period` must be non-zero when a periodic quota is enabled.
- `cooldown` limits the minimum interval between executions.
- `validAfter` prevents use before activation.
- `expiry` prevents use after expiration.
- `active` is a hard enable/disable switch.

Avoid ambiguous sentinel values where possible. Document every zero-value meaning.

---

# 8. Policy Lifecycle

## 8.1 Create policy

An authorized administrator creates a policy.

Requirements:

- Validate all fields.
- Assign a unique policy ID.
- Store the policy.
- Emit `PolicyCreated`.

## 8.2 Update policy

Only the designated administrative authority may modify a policy.

Important rule:

> Updating a policy must not accidentally preserve stale spending/cooldown state when changing fields that alter the security semantics.

Define explicitly which fields can be updated and whether changing them resets accounting state.

Recommended V1 behavior:

- Administrative policy updates either reset affected accounting fields or are rejected while accounting state is active.
- Never silently reinterpret old state under new quota parameters.

## 8.3 Disable policy

An authorized administrator can disable a policy immediately.

A disabled policy must fail every execution path.

## 8.4 Delete policy

Prefer a soft-delete/disable model for V1 unless permanent deletion is required.

If deletion exists, ensure old policy IDs cannot become valid again through ID reuse.

---

# 9. Execution Flow

The main execution function should conceptually perform:

```text
Caller
  |
  v
Policy Engine
  |
  +--> policy exists?
  +--> policy active?
  +--> current time valid?
  +--> caller authorized?
  +--> target matches?
  +--> selector matches?
  +--> msg.value <= maxValue?
  +--> cooldown satisfied?
  +--> periodic quota satisfied?
  +--> update accounting state
  |
  v
Target.call{value: msg.value}(calldata)
  |
  +--> success -> return target result
  +--> failure -> revert without leaving inconsistent policy state
```

## Critical ordering requirement

The implementation must ensure that a failed target call does **not** permanently consume quota or cooldown state unless that behavior is intentionally justified and documented.

Recommended approach:

1. Validate.
2. Calculate new accounting state.
3. Perform external call.
4. Commit state in a way that preserves Solidity revert atomicity.

The implementation should rely on transaction-level atomicity rather than attempting complex manual rollback logic.

---

# 10. Policy Matching

V1 should support exact matching:

```text
allowedCaller == msg.sender
AND
policy.target == target
AND
policy.selector == bytes4(calldata[0:4])
AND
policy time constraints are valid
AND
value constraints are valid
```

Do not add wildcard targets/selectors/callers unless the wildcard behavior is explicitly specified and separately tested.

Exact matching keeps the initial security model understandable.

---

# 11. Native-Token Spending Limits

## Per-call limit

For a policy:

```text
msg.value <= maxValue
```

must always hold.

## Periodic limit

Track native-token value spent under the policy during the configured period.

Example:

```text
periodLimit = 10 ETH
period = 1 day
spent = 6 ETH
new call = 5 ETH
=> revert
```

### Period reset

Define the period mathematically rather than relying on human calendar days.

Recommended model:

```text
periodStart = floor(block.timestamp / period) * period
```

However, compare this model against a rolling-window model before implementation. Pick exactly one model for V1 and document it.

The accounting model must be deterministic and resistant to edge cases around period boundaries.

---

# 12. Cooldown

For a successful execution:

```text
block.timestamp >= lastExecution + cooldown
```

must hold.

Example:

```text
cooldown = 1 hour
lastExecution = 10:00
next valid execution >= 11:00
```

Consider overflow-safe arithmetic and define behavior for `cooldown == 0`.

Recommended:

```text
cooldown == 0 => cooldown disabled
```

---

# 13. Time Validity

A policy is executable only when:

```text
block.timestamp >= validAfter
AND
(expiry == 0 OR block.timestamp < expiry)
```

Recommended interpretation:

- `validAfter == 0`: active immediately.
- `expiry == 0`: no expiry.

Avoid allowing an already-expired policy to execute because of boundary-condition mistakes.

Choose and document whether `expiry` is inclusive or exclusive. Recommended: exclusive.

---

# 14. Delegated Execution / EIP-712

This is an optional V1 extension and should only be implemented after direct execution is correct.

A signer should be able to authorize a specific execution with:

- policy ID
- target
- selector/calldata hash
- value
- nonce
- deadline
- chain ID/domain separator

Required protections:

- Nonce cannot be reused.
- Signature must be bound to the intended chain/domain.
- Deadline must be enforced.
- Signature must be bound to the exact action.
- Do not allow one signature to authorize an arbitrary different calldata payload.

Use OpenZeppelin's maintained cryptographic primitives where appropriate rather than implementing signature verification from scratch.

---

# 15. Batch Execution

Batch execution is optional and should be implemented only after single-call execution is fully tested.

A batch must define:

- Maximum number of calls.
- Whether every call uses the same policy.
- Whether each call consumes quota independently.
- Whether aggregate native-token value is checked.
- How failure is handled.

Recommended V1 rule:

> Batch execution is atomic: if any call fails, the complete transaction reverts.

Do not silently skip failed calls.

The implementation must prevent a batch from bypassing per-call or aggregate limits.

---

# 16. Read-Only Simulation

Provide a view function such as:

```solidity
function checkPolicy(
    uint256 policyId,
    address caller,
    address target,
    uint256 value,
    bytes calldata data
) external view returns (bool allowed, bytes32 reason);
```

The exact return type can change, but the result should clearly explain why a call is denied.

Do not make the simulation logic materially different from the real execution checks.

The safest architecture is to share internal validation logic between simulation and execution.

---

# 17. Access Control

Separate administrative powers clearly.

Suggested roles:

```text
DEFAULT_ADMIN_ROLE
POLICY_ADMIN_ROLE
PAUSER_ROLE
```

Possible responsibilities:

- `DEFAULT_ADMIN_ROLE`: administer roles and high-impact configuration.
- `POLICY_ADMIN_ROLE`: create/update/disable policies.
- `PAUSER_ROLE`: emergency pause.

Do not grant all roles to arbitrary operational callers.

If OpenZeppelin AccessControl is used, verify the exact installed version and APIs instead of assuming older interfaces.

---

# 18. Pause / Emergency Controls

The engine should support a global emergency pause.

When paused:

- All policy-controlled executions revert.
- Policy creation/update behavior must be explicitly defined.
- Read-only inspection should continue working.
- Unpausing requires the correct authority.

Pause must cover every execution entry point, including future batch and signature-based execution functions.

Avoid an emergency mechanism that can be bypassed by calling another internal/public path.

---

# 19. Reentrancy and External Calls

The engine eventually performs arbitrary external calls. Treat every target as malicious.

Security requirements:

- Never assume target contracts are trusted.
- Carefully define checks-effects-interactions behavior.
- Protect against reentrant execution where it could violate policy accounting.
- Consider whether a malicious target can re-enter the Policy Engine using another policy.
- Test nested and recursive execution attempts.
- Ensure pause state and accounting cannot be bypassed through reentrancy.

Use a reentrancy guard only where it solves a clearly identified invariant. Do not add modifiers mechanically.

---

# 20. ETH / Native Token Handling

The engine must define whether it can receive native tokens outside policy-controlled execution.

Recommended V1 behavior:

- Direct unsolicited ETH transfers are either rejected or explicitly accounted for.
- Executions may forward native tokens only through the authorized execution path.
- Avoid accidentally trapping funds without a documented recovery mechanism.

If a recovery function exists, it must have strict authorization and must not allow the recovery authority to violate policy guarantees.

---

# 21. Failure Handling

Use custom errors rather than long revert strings where practical.

Examples:

```solidity
error PolicyNotFound(uint256 policyId);
error PolicyDisabled(uint256 policyId);
error UnauthorizedCaller(address caller);
error TargetMismatch(address expected, address actual);
error SelectorMismatch(bytes4 expected, bytes4 actual);
error PolicyNotActive(uint256 policyId);
error PolicyExpired(uint256 policyId);
error ValueLimitExceeded(uint256 requested, uint256 maximum);
error PeriodLimitExceeded(uint256 requested, uint256 remaining);
error CooldownActive(uint256 nextAllowedAt);
error EnginePaused();
```

Do not expose misleading errors where internal state or caller identity could be confused.

---

# 22. Events

At minimum:

```solidity
event PolicyCreated(uint256 indexed policyId, address indexed caller, address indexed target, bytes4 selector);
event PolicyUpdated(uint256 indexed policyId);
event PolicyDisabled(uint256 indexed policyId);
event PolicyEnabled(uint256 indexed policyId);
event PolicyExecuted(uint256 indexed policyId, address indexed caller, address indexed target, uint256 value);
event PolicyExecutionFailed(uint256 indexed policyId, address indexed target);
event EnginePaused(address indexed account);
event EngineUnpaused(address indexed account);
```

Events should expose enough indexed information for monitoring without logging unnecessarily large calldata blobs.

---

# 23. Security Invariants

These are core properties that must remain true under all reachable states.

## Authorization invariants

1. A caller can execute only a policy explicitly authorizing that caller.
2. A policy can execute only its configured target.
3. A policy can execute only its configured function selector.
4. Disabled or expired policies cannot execute.
5. Paused state blocks every policy execution entry point.

## Value invariants

6. `msg.value <= maxValue` for every successful policy execution.
7. Period spending never exceeds `periodLimit`.
8. Batch execution cannot bypass individual or aggregate limits.

## Temporal invariants

9. Execution cannot occur before `validAfter`.
10. Execution cannot occur after `expiry`.
11. Cooldown cannot be bypassed by repeated calls in the same transaction.

## State/accounting invariants

12. Failed target calls do not leave permanently consumed policy quota/cooldown state.
13. Policy ID reuse cannot resurrect stale permissions.
14. Policy updates cannot unexpectedly reinterpret historical accounting state.
15. Reentrancy cannot create an unauthorized second execution or exceed quotas.

## Signature invariants

If signatures are implemented:

16. A signed action cannot be replayed.
17. A signature is bound to the intended chain/domain.
18. A signature cannot be reused for altered calldata, target, value, policy, or deadline.

---

# 24. Threat Model

Assume the following actors may be malicious:

- Untrusted users
- Unauthorized operational callers
- Compromised target contracts
- Malicious ERC-1271 contract wallets if supported
- Malicious callback contracts
- Contracts attempting reentrancy
- Attackers racing policy changes
- Attackers exploiting timestamp boundaries
- Attackers abusing batch execution
- Attackers replaying signatures
- Privileged actors with insufficiently restricted roles

Do not rely on:

- Honest target behavior
- Honest calldata
- Honest return data
- EOAs only
- Frontends enforcing policy
- Off-chain monitoring for a security guarantee

The contract itself must enforce all critical constraints.

---

# 25. Adversarial Test Suite

Testing is a first-class deliverable.

## Unit tests

Cover:

- Policy creation
- Policy update
- Enable/disable
- Unauthorized admin actions
- Exact target matching
- Exact selector matching
- Caller matching
- Value limits
- Period quotas
- Cooldowns
- `validAfter`
- `expiry`
- Pause/unpause
- Successful execution
- Reverting target
- Return-data forwarding

## Negative tests

Explicitly test:

- Wrong caller
- Wrong target
- Wrong selector
- Zero/invalid configuration
- Expired policy
- Premature policy
- Exceeded per-call limit
- Exceeded period limit
- Cooldown violation
- Paused engine
- Unknown policy ID
- Malformed calldata
- Reentrancy attempt
- Nested execution attempt
- Batch quota bypass attempt
- Policy-update race scenarios

## Fuzz tests

Fuzz:

- Timestamps
- Value amounts
- Period lengths
- Cooldowns
- Policy IDs
- Callers
- Targets
- Selectors
- Repeated execution sequences
- Policy updates between executions
- Batch sizes and values

Important fuzz property:

> No sequence of valid external calls may produce a successful execution that violates any policy invariant.

## Invariant testing

Build a stateful test handler that creates policies, mutates them, executes calls, pauses/unpauses, advances time, and attempts malicious actions.

Continuously assert the security invariants from Section 23.

## Malicious target contract

Create a dedicated adversarial target capable of:

- Reverting
- Returning arbitrary bytes
- Re-entering the engine
- Calling another target
- Attempting nested policy execution
- Sending unexpected native tokens

---

# 26. Suggested Contract Architecture

Keep V1 modular but small.

Recommended components:

```text
src/
├── PolicyEngine.sol
├── interfaces/
│   ├── IPolicyEngine.sol
│   └── IPolicyTarget.sol          # optional, only if actually needed
├── libraries/
│   └── PolicyLib.sol              # optional
└── mocks/
    ├── MaliciousTarget.sol
    └── ReentrantTarget.sol
```

The exact file layout can change if a simpler architecture improves safety.

### `PolicyEngine.sol`

Responsible for:

- Policy lifecycle
- Authorization
- Policy validation
- Execution
- Accounting
- Pause state
- Events

### `IPolicyEngine.sol`

Expose stable integration methods and events without exposing implementation details.

Avoid unnecessary libraries and interfaces in V1.

---

# 27. Data Model

Recommended mapping:

```solidity
mapping(uint256 => Policy) private policies;
uint256 private nextPolicyId;
```

If indexing policies by caller/target is needed for read performance, add secondary indexes only after correctness is established.

Do not maintain redundant state unless the consistency invariants are clear.

---

# 28. Integration API

Core execution function should conceptually look like:

```solidity
function execute(
    uint256 policyId,
    address target,
    bytes calldata data
) external payable returns (bytes memory result);
```

The implementation must validate that:

```text
policy.target == target
policy.selector == bytes4(data)
```

and:

```text
msg.value
```

is within policy limits.

The API may be refined during implementation, but the caller must never be able to substitute a different target or selector without the policy checks catching it.

---

# 29. Gas / Efficiency Requirements

Do not optimize prematurely, but avoid obvious storage waste.

Priorities:

1. Correct authorization
2. Correct accounting
3. Correct external-call behavior
4. Clear storage model
5. Reasonable gas usage

Potential optimizations:

- Pack timestamp/boolean fields where safe.
- Use `calldata` for external parameters.
- Avoid unnecessary dynamic storage.
- Avoid repeated hashing/computation.

Do not trade away readability or safety for marginal gas savings.

---

# 30. Access-Control Hardening

Test role-management itself.

Required questions:

- Who can grant `POLICY_ADMIN_ROLE`?
- Who can revoke it?
- Can a policy administrator pause the system?
- Can a pauser create policies?
- What happens if the last administrator loses access?
- Can role changes race with a policy execution?

Document the authority model in `SECURITY.md`.

For a portfolio project, a clear privilege model is more important than adding many roles.

---

# 31. Repository Requirements

Recommended stack:

- Solidity `^0.8.24` or a current stable compiler explicitly chosen for the project
- Foundry
- OpenZeppelin Contracts for mature access-control/security primitives where appropriate
- MIT license

Before implementation:

- Pin dependency versions.
- Do not rely on undeclared transitive dependencies.
- Keep the repository reproducible.

Required repository files:

```text
README.md
SECURITY.md
LICENSE
foundry.toml
src/
test/
script/
```

CI should run at minimum:

```text
forge fmt --check
forge build
forge test
```

Add static analysis such as Slither when practical.

---

# 32. Documentation Requirements

`README.md` should explain:

1. What the Policy Engine does.
2. Why it exists.
3. Architecture.
4. Policy lifecycle.
5. Execution flow.
6. Example integration.
7. Threat model.
8. Test strategy.
9. Known limitations.
10. Explicit statement that the project is not audited unless an independent audit has actually occurred.

`SECURITY.md` should describe:

- Trust assumptions
- Privileged roles
- Security invariants
- Supported compiler/dependency versions
- Reporting process
- Known non-goals

Never claim security guarantees that the code/tests do not establish.

---

# 33. Implementation Phases

## Phase 1 — Core Engine

Implement only:

- Policy struct
- Policy IDs
- Policy creation
- Policy enable/disable
- Exact caller/target/selector matching
- Per-call value limit
- Basic time validity
- Execute
- Events
- Custom errors

### Exit criteria

All core unit tests pass and no execution path bypasses the checks.

---

## Phase 2 — Accounting Controls

Add:

- Periodic quota
- Cooldown
- Accounting reset logic
- Boundary-condition tests
- Invariant tests

### Exit criteria

Fuzz/invariant testing cannot find a successful state violating quota or cooldown invariants.

---

## Phase 3 — Emergency Controls

Add:

- Pause/unpause
- Role separation
- Role-management tests
- Reentrancy analysis/tests

### Exit criteria

Every execution entry point respects pause state and privileged operations are correctly isolated.

---

## Phase 4 — Simulation API

Add:

- `checkPolicy()` or equivalent
- Machine-readable denial reason
- Shared validation logic

### Exit criteria

Simulation results match actual execution eligibility for the same inputs.

---

## Phase 5 — Advanced Execution

Only after the core system is stable, consider:

- EIP-712 delegated execution
- Batch execution
- More advanced policy selectors

Each feature needs its own threat model and tests.

---

# 34. Definition of Done

The V1 project is complete only when all of the following are true:

- [ ] Core contracts compile with pinned dependencies.
- [ ] Policy lifecycle is fully implemented.
- [ ] Exact caller/target/selector authorization works.
- [ ] Per-call native-token limits work.
- [ ] Periodic quotas work.
- [ ] Cooldowns work.
- [ ] Activation/expiry rules work.
- [ ] Pause/unpause works.
- [ ] External-call failures revert safely.
- [ ] Reentrancy scenarios are tested.
- [ ] State accounting invariants are covered.
- [ ] Fuzz tests are included.
- [ ] Stateful invariant tests are included.
- [ ] Malicious targets are included in the test suite.
- [ ] Events and custom errors are implemented.
- [ ] README explains the architecture and limitations.
- [ ] SECURITY.md documents trust assumptions and invariants.
- [ ] CI runs formatting, build, and tests.
- [ ] No TODO is left for a security-critical path.
- [ ] No feature is claimed to be implemented unless it exists and is tested.

---

# 35. Muse Spark Implementation Rules

Use this section as the primary engineering constraints when generating the project.

## Non-negotiable rules

1. **Do not rewrite the project from scratch after implementation has started.** Make incremental, reviewable changes.
2. **Do not invent dependencies, APIs, OpenZeppelin functions, Foundry features, or compiler behavior.** Verify the installed versions and actual APIs before using them.
3. **Do not silently add product features outside this PRD.** Record any necessary deviation in the implementation notes.
4. **Do not claim a vulnerability is fixed unless a regression test proves the behavior.**
5. **Do not claim the project is secure/audited.** Tests reduce risk; they do not constitute an audit.
6. **Prefer fail-closed behavior.**
7. **Use custom errors and explicit checks for security-critical conditions.**
8. **Treat every external target as malicious.**
9. **Never rely on frontend validation for authorization or spending limits.**
10. **Keep single-call execution correct before implementing batching or signatures.**
11. **Do not use `via_ir` unless explicitly required by the project configuration.**
12. **Do not weaken compiler warnings or tests to make the build pass.**
13. **Do not delete or disable tests just because they fail after a code change.** Fix the implementation or update the test only when the intended specification has genuinely changed.
14. **Do not leave placeholder security logic such as `TODO: add check later`.**
15. **Do not introduce upgradeability just for convenience.**

## Development workflow

For each phase:

```text
Read PRD
  -> inspect repository/dependencies
  -> implement smallest change
  -> compile
  -> run relevant unit tests
  -> run full test suite
  -> add regression/fuzz/invariant coverage
  -> inspect diff
  -> document decisions
```

Before modifying a security-critical contract, inspect the current code and tests first.

---

# 36. Required Test Matrix

At minimum, create explicit tests for this matrix:

| Area | Valid case | Invalid case |
|---|---|---|
| Caller | Authorized caller executes | Unauthorized caller reverts |
| Target | Exact target | Different target reverts |
| Selector | Exact selector | Different selector reverts |
| Value | At limit | Above limit reverts |
| Period | Within quota | Above remaining quota reverts |
| Cooldown | After cooldown | Before cooldown reverts |
| Start time | After `validAfter` | Before `validAfter` reverts |
| Expiry | Before expiry | At/after expiry according to documented semantics |
| Pause | Engine active | Engine paused |
| Policy | Existing/active | Unknown/disabled |
| Target call | Target succeeds | Target reverts |
| Reentrancy | Normal execution | Malicious reentrant attempt |
| Batch | All valid | One invalid call causes defined failure behavior |
| Signature | Fresh valid signature | Replay/altered calldata/wrong domain |

The signature and batch rows are required only if those features are implemented.

---

# 37. Example Policy

Example policy:

```text
Policy ID: 7
Caller:      0xOperator
Target:      0xTreasuryModule
Selector:    execute(bytes)
Max value:   2 ETH
Period:      24 hours
Period cap:  10 ETH
Cooldown:    1 hour
Valid after: 2026-01-01
Expiry:      2027-01-01
Active:      true
```

Expected behavior:

```text
0.5 ETH call -> allowed if all other checks pass
2.0 ETH call -> allowed if quota remains
2.1 ETH call -> revert
10 ETH already spent in current period -> new value call reverts
Execution 10 minutes after previous success with 1h cooldown -> revert
Execution after expiry -> revert
Different caller -> revert
Different target -> revert
Different selector -> revert
Paused engine -> revert
```

---

# 38. Future Extensions

Do not implement these in V1 unless there is a compelling reason:

- ERC-20 amount-aware spending policies
- ERC-721/ERC-1155 transfer policies
- Contract allowlists/denylists
- Multiple authorized callers per policy
- Role-based policy matching
- Function argument constraints
- Merkle-tree policy authorization
- EIP-1271 smart-wallet signatures
- Account-abstraction/paymaster integration
- Cross-chain policy synchronization
- Time-of-day/day-of-week policies
- Oracle-based conditions
- Governance-controlled policy templates

Each extension should be treated as a new security surface, not a small convenience feature.

---

# 39. Success Criteria

The project succeeds when it demonstrates that a single reusable contract can enforce **fine-grained authorization + value limits + temporal restrictions + accounting quotas** around arbitrary external contract calls while remaining understandable and heavily tested.

The portfolio value should come from:

- Strong threat modeling
- Explicit invariants
- Stateful fuzzing
- Adversarial contracts
- Clean architecture
- Reproducible builds
- Clear documentation
- Carefully bounded feature scope

The project should feel like **security infrastructure**, not a demo token contract.

---

# 40. Final Engineering Directive

Build the smallest secure version that satisfies this PRD.

When there are multiple implementation choices, prefer the one with:

1. Fewer trust assumptions
2. Fewer external dependencies
3. Fewer mutable states
4. Simpler invariants
5. Easier formal reasoning
6. Stronger testability
7. Clearer integration semantics

Do not optimize for the number of features.

Optimize for **correctness, auditability, and demonstrable security engineering**.
