# SECURITY.md — On-Chain Policy Engine

**Status: not audited.** This document states what the code actually enforces.
Nothing here is a guarantee; verify against `src/` and `test/`.

## Trust assumptions

- The deployer (bootstrap admin) is honest during setup and then moves to a
  least-privilege role layout (ideally multisig / timelock holding
  `DEFAULT_ADMIN_ROLE`).
- Block timestamps move forward monotonically within normal miner/validator
  tolerance; `validAfter`/`expiry`/cooldown/windows inherit timestamp semantics.
- Chain ID + verifying-contract binding of EIP-712 holds (no fork replay beyond
  what the domain separator covers).
- OpenZeppelin Contracts v5.7.0 primitives (AccessControl, Pausable,
  ReentrancyGuard, EIP712, ECDSA) behave as documented.

## Privileged roles

| Role | Powers | Must NOT be held by |
|---|---|---|
| `DEFAULT_ADMIN_ROLE` | grant/revoke roles, `setMaxBatchSize`, `sweepStuckETH` | operators, relayers, targets |
| `POLICY_ADMIN_ROLE` | create/update/disable/delete policies | operators, pausers-only accounts |
| `PAUSER_ROLE` | `pause` / `unpause` (execution kill-switch) | policy admins (separation of duties) |

The deployer receives all three for bootstrap and should revoke down. Losing all
`DEFAULT_ADMIN_ROLE` holders bricks role recovery (immutability trade-off).
Role changes take effect immediately and race safely with execution because each
execution validates against current storage atomically.

## Security invariants (all tested)

1. Caller executes only a policy explicitly authorizing it (`address(0)` =
   documented any-caller wildcard, never an accident).
2. Only the configured target.
3. Only the configured selector (`bytes4(0)` = documented any-selector wildcard).
4. Disabled/deleted/expired/premature policies never execute; IDs never reused.
5. Pause blocks `execute`, `executeDelegated`, `executeBatch`; views, admin
   lifecycle, and signer nonce invalidation keep working.
6. `msg.value <= maxValue` on every success; window spend never exceeds
   `periodLimit`; batch `sum(values) == msg.value` with per-leg validation and
   error args ordered `(expected = sum, actual = msg.value)`.
7. Cooldown enforced across updates (`lastExecution` preserved).
8. Failed target calls consume no quota/cooldown (atomic revert).
9. Updates reset period accounting (no reinterpretation of old state).
10. Reentrancy/nested execution cannot double-spend (state committed before the
    call + `nonReentrant` single guard).
11. Signatures: per-signer nonce, chain/contract domain binding, exact
    calldata+value+deadline binding; `deadline == 0` is always expired. A
    signer can cancel every pending intent by calling
    `invalidateDelegationNonce` with a strictly larger nonce.
12. The engine is never a policy target (`target == address(this)` rejected at
    config time); failure-path returndata is capped at
    `MAX_FAILURE_RETURNDATA` (2048 bytes); `sweepStuckETH` reports
    `RescueFailed` when the recipient rejects ETH.

## Versions

Solidity `0.8.24` (pinned in `foundry.toml`), OpenZeppelin `v5.7.0`,
forge-std `v1.16.2`. No floating dependencies.

## Reporting

Do not open public issues for suspected vulnerabilities. Contact the repository
owner directly with: affected commit, reproduction (Foundry test preferred),
impact assessment. Expect acknowledgment, private triage, and a regression test
before any fix is described as complete.

## Explicit non-goals (not security boundaries)

ERC-20/NFT business logic beyond the `argAmountCap` guard, oracles,
cross-chain messaging, governance, account abstraction, social recovery,
upgradeability. Treat any such extension as a new security surface.
