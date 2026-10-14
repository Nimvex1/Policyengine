# Security Audit — On-Chain Policy Engine

**Target:** `src/PolicyEngine.sol` (commit state of this repository)
**Compiler:** solc 0.8.24 (pinned) · **Framework:** Foundry · **Dependencies:** OpenZeppelin v5.7.0, forge-std v1.16.2
**Tools:** Slither 0.11.6, manual invariant review, 9 adversarial PoC tests (`test/AuditPoC.t.sol`)
**Suite:** 66/66 tests passing · `forge fmt --check` clean

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 (1 found, 1 resolved) |

**Verdict: no exploitable vulnerability found affecting funds, access control, or execution integrity.** Every candidate attack path identified during source review was either gated by roles/`nonReentrant`/strict validation, or failed the audit's false-positive gate (by-design, theoretical, or configuration-dependent with no attacker-controlled input).

The single Low finding (an unreachable-on-chain event presented as telemetry) was resolved: the documentation now states the actual semantics (trace/simulation-only), the event is retained intentionally as PRD §22-mandated telemetry, and a regression test pins the behavior.

## System Model

**Assets:** native ETH balance of the engine (only force-fed funds + in-flight batch `msg.value`); the policy state machine (who may call what, under which limits).

**Trust assumptions (per SECURITY.md):**
- `DEFAULT_ADMIN_ROLE` — trusted (role granting, `sweepStuckETH`, batch-size config).
- `POLICY_ADMIN_ROLE` — trusted to author policy parameters (limits, callers, targets). Quota accounting exists to constrain *operators*, not the policy author.
- `PAUSER_ROLE` — trusted, may pause indefinitely (documented centralization).
- Policy signers of allowed signers (delegated path) — trusted to sign valid intents; signature is bound to `chainid`, contract address, policyId, target, dataHash, `msg.value`, nonce, deadline. A signer may cancel pending intents at any time via `invalidateDelegationNonce`.

**Execution paths:** all three (`execute`, `executeBatch`, `executeDelegated`) are `nonReentrant whenNotPaused`, validate `_exists → paused check → validity window → cooldown → caller → selector → value cap → period quota` before any external call, and forward exactly the caller's specified value — never `address(this).balance`. The target call is made with a zero-size output area and only bounded failure returndata is copied back (see hardening below).

**ETH invariants:** `receive`/`fallback` revert (`DirectEthNotAccepted`); batch enforces `sum(values) == msg.value`; execution never forwards more than explicitly requested; stuck ETH recoverable only via `DEFAULT_ADMIN` `sweepStuckETH` (`RescueFailed` if the recipient rejects ETH).

## Verification Performed

### Automated
- Slither 0.11.6 (full detectors on `src/`): no reentrancy-eth, no arbitrary-reach, no delegatecall, no `tx.origin`, no signature-recovery detectors. 22 results across 11 detectors, all gated below.

### Adversarial PoCs (`test/AuditPoC.t.sol`, 9/9 pass = all paths fail closed)
| # | Attack path | Result |
|---|---|---|
| 1 | Policy target = engine itself → pivot to `pause`/`execute`/`sweepStuckETH` | **Blocked** — `_validateParams` rejects `target == address(this)` at config time; no such policy can ever exist; funds untouched |
| 2 | Force-fed ETH forwarded by `execute` | **Blocked** — balance never read; target received exactly `msg.value` |
| 3 | Batch leg target spoof (≠ policy target) | **Blocked** — `TargetMismatch`, atomic revert |
| 4 | Same policy twice in one batch to bypass cooldown | **Blocked** — leg 2 reverts, leg 1 state rolled back, `execCount == 0` |
| 5 | Batch ETH smuggle (`msg.value > sum(values)`) | **Blocked** — `BatchValueMismatch(expected=total, actual=msg.value)`, balance stays 0 |
| 6 | Wildcard policy via `executeDelegated` | **Consistent** — same power as direct path, no escalation delta |
| 7 | Restricted policy, foreign signer self-signs | **Blocked** — `InvalidSignature` |
| 8 | Relayer substitutes signed `msg.value` | **Blocked** — value bound into digest; correct value then succeeds |
| 9 | Execute after `deletePolicy` | **Blocked** — `PolicyNotFound` checked before recovery |

### Slither findings — false-positive gate (22 results, 11 detectors)
| Detector | Location | Disposition |
|---|---|---|
| `arbitrary-send-eth` | `sweepStuckETH` (`PolicyEngine.sol:216-222`) | **By design** — `onlyRole(DEFAULT_ADMIN)` + `nonReentrant`; admin already trusted; moves only force-fed ETH |
| `arbitrary-send-eth` | `MaliciousTarget.pay()` | **Mock**, not production |
| `divide-before-multiply` | `_windowStart` (`PolicyEngine.sol:580`) | **Intentional** — floor-anchor is the feature; integer floor has no exploitable rounding |
| `incorrect-equality` | `_check:434`, `_revertWithReason:480` | **Intentional** window-identity comparison, not value equality |
| `locked-ether` | `SimpleTarget` | **Mock** |
| `uninitialized-local` | `executeBatch.total` (`PolicyEngine.sol:299`) | **FP** — `uint256` zero-init accumulation pattern |
| `unused-return` | `MaliciousTarget.pay()` | **Mock** |
| `timestamp` | `executeDelegated:252`, `_commitAccounting:383`, `_check:411/412/430/434`, `_revertWithReason:480` | **Inherent** — ±15s manipulability standard; no exploitable path |
| `assembly` | `_executeValidated:341/352`, `_failureReturndata:368`, `_check:421/443`, `_revertWithReason:470/488`, `RevertBomb` (mock) | **Bounds-checked, memory-safe annotated** |
| `cyclomatic-complexity` | `_revertWithReason` (`PolicyEngine.sol:453-498`) | Style only |
| `low-level-calls` | `sweepStuckETH:220`, `MaliciousTarget` (mock) | **Accepted** — result checked (`RescueFailed`); mock otherwise |
| `immutable-states` | `MaliciousTarget.engine` | **Mock** |

Note: the `calls-loop` detector no longer fires because the target call is now a raw assembly `call` (bounded batch ≤ 64, `nonReentrant`, atomic — risk profile unchanged).

## Findings

## [Low → Resolved] `PolicyExecutionFailed` event is unreachable on-chain (emitted-then-reverted)

**Location:** `src/PolicyEngine.sol:320-361` (`_executeValidated`, emit at `:348`); interface declared in `src/interfaces/IPolicyEngine.sol`.

**Original report:** any failing target call executes `emit PolicyExecutionFailed(policyId, target); revert TargetCallFailed(policyId, returnData);` — the `revert` rolls back the log, so the event can never be observed by on-chain indexers while docs presented it as the failure telemetry signal.

**Resolution:** documentation (interface NatSpec + this file) now states the actual semantics — the event is trace/simulation-only and the canonical on-chain signal is the `TargetCallFailed` custom error. The event is retained intentionally: PRD §22 mandates it, it is visible to tracing/simulation tooling, and removing it would reduce observability without any security gain. Regression test: `test_ExecutionFailedEvent_OnlyInRevertedFrame` (`test/PolicyEngine.t.sol:836`) pins that a success event can never appear in a reverted execution.

**Confidence:** High (deterministic EVM revert semantics).

---

## Round-2 hardening applied

1. **False NatSpec fixed** — `POLICY_ADMIN_ROLE` no longer claims to tune batch size limits (`PolicyEngine.sol:46`; that is `DEFAULT_ADMIN_ROLE` at `:188`).
2. **`BatchValueMismatch` argument order corrected** — now `(expected = sum(leg values), actual = msg.value)` (`PolicyEngine.sol:303`), matching the error's NatSpec.
3. **`RescueFailed()` replaces `TargetCallFailed(0, "")`** in `sweepStuckETH` (`PolicyEngine.sol:220-221`) — a mislabeled error was misleading per PRD §21.
4. **Self-target rejected at config time** — `_validateParams` reverts `InvalidPolicyConfig()` for `target == address(this)` (`PolicyEngine.sol:588`), closing the whole self-call hazard class regardless of future refactors (was observation #4; PoC #1 rewritten to assert config-time rejection).
5. **Bounded failure returndata** — the target call is made with a zero-size output area (no unbounded EVM copy into engine frames); on failure at most `MAX_FAILURE_RETURNDATA` (2048 bytes, `PolicyEngine.sol:95`) is copied into `TargetCallFailed` via `_failureReturndata` (`:367-376`). Success-path returndata is copied in full by design — silently truncating a successful result is worse than letting an oversized return gas-out the whole atomic call (fail closed; quota/cooldown roll back). Regression test: `test_FailureReturndata_Bounded` (`test/PolicyEngine.t.sol:819`) with a 64 KiB revert-bomb mock.
6. **`invalidateDelegationNonce(newNonce)`** (`PolicyEngine.sol:275`, interface `:184`) — a signer can cancel all pending delegated intents by advancing their own nonce (signatures bind an exact nonce). Self-service (no role), works while paused (revoking a leaked signature must never be blocked), reverts `InvalidNonce()` if not increasing, emits `DelegationNonceInvalidated`.
7. **`PolicyConfigUpdated` event** (interface `:116`, emitted on create and update via `_emitConfigUpdated`, `PolicyEngine.sol:560`) — indexers can detect silent redirection of a live policy ID; the PRD-mandated `PolicyCreated`/`PolicyUpdated` signatures are untouched.
8. **`REASON_PAUSED` maps to OZ `EnforcedPause()`** in `_revertWithReason` — unreachable today (`whenNotPaused` fires first) but correct if a future entry point omits the modifier.
9. **`getPolicies` exposed on the interface** (`IPolicyEngine.sol:200`) — the batch reader was contract-only.
10. **CI** — Foundry pinned to v1.8.3, `evm_version = "cancun"` pinned in `foundry.toml`, Slither job added (`--fail-none`, informational).

## Observations / Hardening (not scored as findings — failed the gate)

1. ~~**Doc comment mismatch**~~ — resolved (hardening #1).
2. ~~**`BatchValueMismatch` error-argument naming**~~ — resolved (hardening #2).
3. **`uint32 execCount` / `uint32 version` overflow** — after 4,294,967,295 executions a policy's counter wraps, which could reset quota display/`version` history. **Theoretical:** at realistic gas costs this is economically unreachable; gate rejects it as a finding. Optional hardening: check overflow on increment.
4. ~~**No explicit `target != address(self)` check**~~ — resolved (hardening #4).
5. **Integration hazard: `msg.sender` at the target is the engine** — targets must not grant the engine address privileges unless *every possible policy caller* is trusted (SECURITY.md covers trust assumptions; explicit "don't grant engine special rights" line for integrators). Wildcard-caller policies only extend access the direct path would already grant — no escalation delta (PoC #6).
6. **`argAmountCap` ABI-layout fragility** — offsets for dynamic-type functions are admin-configured; a misconfigured offset constrains the wrong bytes. Selector binding makes static-head functions sound; no attacker-controlled input reaches `argOffset`. Configuration responsibility, documented.

## Invariants Verified (all hold)

- **Access:** every state-changing function role-gated (lifecycle also tested for non-admin rejection); no `tx.origin`; no `delegatecall`.
- **Reentrancy:** all 3 execute paths `nonReentrant whenNotPaused`; malicious reenter/nested-policy tests fail atomically.
- **Validation ordering:** `_exists → paused → window → cooldown → caller → selector → value → quota` before any external call.
- **Target integrity:** policy targets are never zero and never the engine itself (`PolicyEngine.sol:583-588`).
- **ETH safety:** receive/fallback revert; batch `sum == msg.value` with correctly ordered error args; execution never touches `address(this).balance` (PoC #2); sweep is admin-only and reports `RescueFailed` on rejection.
- **Failure containment:** target failure returndata copied bounded (≤ 2048 bytes); quota/cooldown consumed only on success (`RevertingTarget_ConsumesNoQuota`); period anchor `_windowStart` floor is monotonic and rollover-safe.
- **Signatures:** EIP-712 domain binds chainid + contract; struct binds policyId, target, dataHash, `value`, `nonce`, `deadline`; signers must be allowed callers (PoCs #7, #8); policy deletion invalidates pending sigs (PoC #9); signers can revoke pending intents via `invalidateDelegationNonce` (3 dedicated tests).

## Verification Commands

```bash
forge fmt --check
forge build
forge test                 # 66 passed
slither . --filter-paths "lib/|test/|script/" --exclude-dependencies --fail-none
```
