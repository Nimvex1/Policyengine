# On-Chain Policy Engine

A reusable smart-contract **authorization layer** — a firewall for smart-contract calls.
Instead of hard-coding spending/allowance rules inside every application contract, an
administrator creates **policies** (who → which contract → which function → how much
ETH → how often → when), and the engine validates + forwards each call atomically.

Built from `prd.md`. Solidity `^0.8.24`, Foundry, OpenZeppelin Contracts `v5.7.0`.
**Self-reviewed in [`AUDIT.md`](AUDIT.md); no external audit.** Tests reduce risk;
they are not a security proof.

## What it does

For one policy execution the engine checks, in fail-closed order:

```
exists? -> active? -> time window? -> caller? -> target? -> selector?
  -> per-call value? -> cooldown? -> periodic quota? -> calldata amount guard?
  -> commit accounting -> target.call{value}(data) -> bubble returndata
     (failure payload capped at MAX_FAILURE_RETURNDATA = 2048 bytes)
```

Any doubt reverts. A failed target call reverts the whole transaction, so quota and
cooldown are **never** consumed by failures (transaction atomicity, no manual rollback).

## Architecture

```
src/
  PolicyEngine.sol            # lifecycle + validation + execution + accounting + pause
  interfaces/IPolicyEngine.sol# structs, errors, events, stable integration API
  mocks/Targets.sol           # SimpleTarget, MaliciousTarget, ForceFeeder,
                              # RevertBomb, EthRejector (tests)
script/Deploy.s.sol           # deployment (broadcaster = bootstrap admin)
test/PolicyEngine.t.sol       # 57 tests: unit + negative + fuzz + adversarial
test/AuditPoC.t.sol           # 9 adversarial PoCs (all paths fail closed)
```

Deliberately **no** `PolicyLib` (the shared `_check` internal keeps simulation and
execution identical without an extra file) and **no upgradeability** (immutable =
smaller attack surface). `getPolicies()` batch reader is part of the stable
interface (`IPolicyEngine`).

## Policy lifecycle

- `createPolicy(params)` — validates config (zero target, self-target, quota
  pair, time range, amount-guard offset), assigns monotonic ID from 1, emits
  `PolicyCreated` + `PolicyConfigUpdated` (full config for indexers). IDs are
  never reused.
- `updatePolicy(id, params)` — overwrites security config, **resets** period
  accounting (old quota state is never reinterpreted), **preserves**
  `lastExecution` (cooldown can't be bypassed by an update), bumps `version`,
  emits `PolicyUpdated` + `PolicyConfigUpdated`.
- `setPolicyActive(id, bool)` — immediate kill-switch per policy.
- `deletePolicy(id)` — hard delete; the ID stays dead forever.

Quota misconfiguration is rejected at creation: `period` and `periodLimit` must be
both zero (disabled) or both non-zero (enabled).

## Execution paths (all pause-guarded, all `nonReentrant`, one shared validator)

| Function | Use case |
|---|---|
| `execute(id, target, data)` payable | Direct call, `msg.sender` authorized |
| `executeDelegated(id, target, data, nonce, deadline, sig)` payable | EIP-712 meta-tx: signer authorizes, anyone relays; `msg.value` bound in signature |
| `executeBatch(calls)` payable | Atomic multi-call; `sum(values) == msg.value`; `len <= maxBatchSize` (default 10, hard cap 64) |
| `checkPolicy(...)` view | Simulation; returns `(allowed, reason)` with short reason codes (`"OK"`, `"COOLDOWN"`, …) |

Signers can also cancel pending delegated intents at any time (even while
paused) with `invalidateDelegationNonce(newNonce)` — jumping the per-signer
nonce forward invalidates every signature bound at or below the old nonce.

## Wildcards and zero values (explicit, documented)

- `allowedCaller == address(0)` → **any** caller (explicit wildcard)
- `selector == bytes4(0)` → **any** calldata (explicit wildcard)
- `maxValue == 0` → only zero-value calls
- `period == 0 && periodLimit == 0` → no periodic quota (anchored windows:
  `floor(now / period) * period`)
- `cooldown == 0` → no cooldown · `validAfter == 0` → immediate ·
  `expiry == 0` → never (else exclusive: `now < expiry`)
- `argAmountCap > 0` → `uint256` at calldata byte `argOffset` must be `<= cap`
  (treasury use case: `transfer(address,uint256)` amount at offset 36)

## Example integration

```solidity
// Admin (once): operator may call pay() on treasury, max 2 ETH/call.
IPolicyEngine.PolicyParams memory p = IPolicyEngine.PolicyParams({
    target: address(treasury),
    allowedCaller: operator,
    selector: Treasury.pay.selector,
    maxValue: 2 ether,
    periodLimit: 10 ether,
    period: 1 days,
    cooldown: 1 hours,
    validAfter: 0,
    expiry: uint64(block.timestamp + 365 days),
    active: true,
    argAmountCap: 0,
    argOffset: 0
});
uint256 id = engine.createPolicy(p);

// Operator (per call): preflight off-chain, then execute.
(bool ok,) = engine.checkPolicy(id, operator, address(treasury), 1 ether, data);
if (ok) engine.execute{value: 1 ether}(id, address(treasury), data);
```

## Threat model (summary)

Untrusted users, compromised/malicious targets, reentrant and nested execution,
policy-update races, timestamp boundaries, batch quota bypass, signature replay,
over-privileged roles. The contract trusts nothing off-chain: no frontend, no
monitoring, no honest-target assumption. Full version in [`SECURITY.md`](SECURITY.md).

## Test strategy

- **Unit/negative**: full PRD matrix (caller, target, selector, value, period,
  cooldown, start, expiry, pause, unknown/disabled policy, malformed calldata),
  plus role-gating (non-admin lifecycle, batch-size, sweep), self-target
  rejection, `getPolicies`, `currentWindowStart`, `PolicyConfigUpdated` events.
- **Fuzz**: value boundaries; stateful quota invariant across window rollovers
  with simulation-vs-execution parity and accounting-drift assertions; cooldown
  window boundary; `argAmountCap` boundary.
- **Adversarial**: `MaliciousTarget` reenters, nests a second policy, pushes
  unexpected ETH back, reverts — all fail atomically with zero state consumed;
  64 KiB revert-bomb proves failure returndata is bounded; force-fed ETH,
  batch spoof/smuggle/cool-down PoCs in `test/AuditPoC.t.sol`.
- **Delegation**: success via relayer, replay/altered-calldata/expiry rejections,
  nonce-invalidation cancellation (stale intent dies, fresh intent works).

```sh
forge fmt --check && forge build && forge test
```

## Known limitations

- `PolicyExecutionFailed` is emitted immediately before the atomic revert, so it
  is visible to tracing/simulation tooling but rolled back on-chain by design;
  the canonical failure signal is `TargetCallFailed`.
- Failure-path returndata is capped at `MAX_FAILURE_RETURNDATA` (2048 bytes) so
  a hostile target cannot balloon the error payload. Success-path returndata is
  returned in full: an adversarial "return bomb" can gas-out its own transaction,
  which reverts atomically (fail closed, no quota consumed) — by design.
- The engine refuses to be a policy target (`target == address(this)` is
  rejected at config time), removing the self-call hazard class entirely.
- The denial error is `PolicyNotActive` (the `PolicyDisabled` name is taken by
  the lifecycle event); both PRD names are otherwise implemented.
- Pause uses OpenZeppelin's `EnforcedPause` (plus `EnginePaused` telemetry);
  admin lifecycle and nonce invalidation stay available while paused by design.
- `sweepStuckETH` rescues only force-fed balance and reverts `RescueFailed` if
  the recipient rejects ETH; normal executions never leave funds in the engine.
  Direct ETH transfers revert.
- No ERC-20/721 awareness beyond the generic `argAmountCap` calldata guard, no
  oracle/cross-chain/governance features (per PRD non-goals).
