// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IPolicyEngine} from "./interfaces/IPolicyEngine.sol";

/// @title PolicyEngine — on-chain firewall for smart-contract calls
/// @notice Enforces programmable authorization + value + quota + temporal rules
///         before forwarding arbitrary calls to approved targets. Fail closed.
///
/// | Zero value            | Meaning (explicit)                              |
/// |-----------------------|-----------------------------------------------|
/// | allowedCaller == 0    | ANY caller authorized (explicit wildcard)       |
/// | selector == 0         | ANY selector/calldata allowed (wildcard)        |
/// | maxValue == 0         | only zero-value calls allowed                   |
/// | period == 0           | no periodic quota (requires periodLimit == 0)   |
/// | periodLimit == 0      | no periodic quota (requires period == 0)        |
/// | cooldown == 0         | no cooldown                                   |
/// | validAfter == 0       | active immediately                            |
/// | expiry == 0           | never expires (else EXCLUSIVE: now < expiry)    |
/// | argAmountCap == 0     | no calldata-amount guard                        |
/// | lastExecution == 0    | never executed                                  |
///
/// @dev Security notes:
///      - Period model is ANCHORED: windowStart = floor(now / period) * period.
///      - Failed target calls revert the whole transaction (atomicity), so quota
///        and cooldown are never consumed by failures. No manual rollback needed.
///      - Accounting is committed BEFORE the external call (checks-effects-
///        interactions); a reentrant call therefore sees updated spent/cooldown
///        state, and `nonReentrant` blocks same-transaction reentry outright.
///      - Pause blocks every execution entry point. Admin lifecycle
///        (create/update/disable/delete) stays available while paused so a bad
///        policy can be fixed during an emergency. Views always work.
///      - Policy IDs are monotonic from 1 and never reused; deleted policies
///        read back as all-zero and are indistinguishable from never-created.
///      - NOT upgradeable by design (smaller attack surface).
contract PolicyEngine is IPolicyEngine, AccessControl, Pausable, ReentrancyGuard, EIP712 {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice May create/update/disable/delete policies.
    bytes32 public constant POLICY_ADMIN_ROLE = keccak256("POLICY_ADMIN_ROLE");
    /// @notice May pause/unpause all execution. Cannot touch policies.
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                           EIP-712 DELEGATION
    //////////////////////////////////////////////////////////////*/

    /// @notice keccak256("Execute(uint256 policyId,address target,bytes32 dataHash,uint256 value,uint256 nonce,uint256 deadline)")
    bytes32 public constant EXECUTION_TYPEHASH = keccak256(
        "Execute(uint256 policyId,address target,bytes32 dataHash,uint256 value,uint256 nonce,uint256 deadline)"
    );

    /*//////////////////////////////////////////////////////////////
                           SIMULATION REASONS
    //////////////////////////////////////////////////////////////*/

    bytes32 private constant REASON_OK = bytes32("OK");
    bytes32 private constant REASON_PAUSED = bytes32("PAUSED");
    bytes32 private constant REASON_NOT_FOUND = bytes32("NOT_FOUND");
    bytes32 private constant REASON_DISABLED = bytes32("DISABLED");
    bytes32 private constant REASON_NOT_STARTED = bytes32("NOT_STARTED");
    bytes32 private constant REASON_EXPIRED = bytes32("EXPIRED");
    bytes32 private constant REASON_UNAUTHORIZED = bytes32("UNAUTHORIZED");
    bytes32 private constant REASON_TARGET = bytes32("TARGET_MISMATCH");
    bytes32 private constant REASON_SELECTOR = bytes32("SELECTOR_MISMATCH");
    bytes32 private constant REASON_MALFORMED = bytes32("MALFORMED");
    bytes32 private constant REASON_VALUE = bytes32("VALUE_EXCEEDED");
    bytes32 private constant REASON_COOLDOWN = bytes32("COOLDOWN");
    bytes32 private constant REASON_PERIOD = bytes32("PERIOD_EXCEEDED");
    bytes32 private constant REASON_AMOUNT = bytes32("AMOUNT_EXCEEDED");

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(uint256 => Policy) private _policies;
    uint256 private _nextPolicyId = 1;
    uint256 private _maxBatchSize = 10;
    mapping(address => uint256) private _signerNonces;

    /// @notice Hard ceiling for `maxBatchSize` (DoS guard: unbounded loops).
    uint256 public constant MAX_BATCH_HARD_CAP = 64;

    /// @notice Cap (bytes) on target returndata bubbled into `TargetCallFailed`
    ///         on the failure path. The call itself is made with a zero-size
    ///         output area, so no unbounded copy happens in the EVM; only this
    ///         bounded copy feeds the error payload (telemetry, not semantics).
    uint256 public constant MAX_FAILURE_RETURNDATA = 2048;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param admin Receives DEFAULT_ADMIN + POLICY_ADMIN + PAUSER for bootstrap.
    ///        Revoke/grants afterwards to reach the steady-state privilege model.
    constructor(address admin) EIP712("PolicyEngine", "1") {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(POLICY_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                           POLICY LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolicyEngine
    function createPolicy(PolicyParams calldata params)
        external
        onlyRole(POLICY_ADMIN_ROLE)
        returns (uint256 policyId)
    {
        _validateParams(params);
        policyId = _nextPolicyId++;
        Policy storage p = _policies[policyId];
        p.target = params.target;
        p.allowedCaller = params.allowedCaller;
        p.selector = params.selector;
        p.maxValue = params.maxValue;
        p.periodLimit = params.periodLimit;
        p.period = params.period;
        p.cooldown = params.cooldown;
        p.validAfter = params.validAfter;
        p.expiry = params.expiry;
        p.active = params.active;
        p.argAmountCap = params.argAmountCap;
        p.argOffset = params.argOffset;
        p.version = 1;
        // accounting starts zero: spentInPeriod, periodStart, lastExecution,
        // totalSpent, execCount are implicitly 0.
        emit PolicyCreated(policyId, params.allowedCaller, params.target, params.selector);
        _emitConfigUpdated(policyId, params);
    }

    /// @inheritdoc IPolicyEngine
    /// @dev Overwrites security config, RESETS period accounting (spent=0,
    ///      window re-anchored) so old quota state is never reinterpreted under
    ///      new parameters, PRESERVES lastExecution so cooldown cannot be
    ///      bypassed by an update, preserves lifetime totals, bumps version.
    function updatePolicy(uint256 policyId, PolicyParams calldata params) external onlyRole(POLICY_ADMIN_ROLE) {
        if (!_exists(policyId)) revert PolicyNotFound(policyId);
        _validateParams(params);
        Policy storage p = _policies[policyId];
        p.target = params.target;
        p.allowedCaller = params.allowedCaller;
        p.selector = params.selector;
        p.maxValue = params.maxValue;
        p.periodLimit = params.periodLimit;
        p.period = params.period;
        p.cooldown = params.cooldown;
        p.validAfter = params.validAfter;
        p.expiry = params.expiry;
        p.active = params.active;
        p.argAmountCap = params.argAmountCap;
        p.argOffset = params.argOffset;
        p.spentInPeriod = 0;
        p.periodStart = params.period > 0 ? _windowStart(params.period, block.timestamp) : 0;
        p.version += 1;
        emit PolicyUpdated(policyId);
        _emitConfigUpdated(policyId, params);
    }

    /// @inheritdoc IPolicyEngine
    function setPolicyActive(uint256 policyId, bool active) external onlyRole(POLICY_ADMIN_ROLE) {
        if (!_exists(policyId)) revert PolicyNotFound(policyId);
        _policies[policyId].active = active;
        if (active) emit PolicyEnabled(policyId);
        else emit PolicyDisabled(policyId);
    }

    /// @inheritdoc IPolicyEngine
    /// @dev Hard delete. The ID is never reused (`_nextPolicyId` only grows),
    ///      so a deleted ID can never become valid again.
    function deletePolicy(uint256 policyId) external onlyRole(POLICY_ADMIN_ROLE) {
        if (!_exists(policyId)) revert PolicyNotFound(policyId);
        delete _policies[policyId];
        emit PolicyDeleted(policyId);
    }

    /// @inheritdoc IPolicyEngine
    function setMaxBatchSize(uint256 newSize) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newSize == 0 || newSize > MAX_BATCH_HARD_CAP) revert InvalidPolicyConfig();
        uint256 old = _maxBatchSize;
        _maxBatchSize = newSize;
        emit MaxBatchSizeUpdated(old, newSize);
    }

    /*//////////////////////////////////////////////////////////////
                         EMERGENCY CONTROLS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolicyEngine
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause(); // emits OZ Paused(msg.sender)
        emit EnginePaused(msg.sender);
    }

    /// @inheritdoc IPolicyEngine
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause(); // emits OZ Unpaused(msg.sender)
        emit EngineUnpaused(msg.sender);
    }

    /// @inheritdoc IPolicyEngine
    /// @dev The engine forwards `msg.value` immediately on every execution, so a
    ///      non-zero balance is always accidental (e.g. force-fed via selfdestruct
    ///      coinbase). Rescue cannot violate policy guarantees: it moves only
    ///      idle balance and never mints execution allowance.
    function sweepStuckETH(address payable to) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        uint256 bal = address(this).balance;
        emit Rescue(to, bal);
        (bool ok,) = to.call{value: bal}("");
        if (!ok) revert RescueFailed();
    }

    /*//////////////////////////////////////////////////////////////
                               EXECUTION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolicyEngine
    function execute(uint256 policyId, address target, bytes calldata data)
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes memory result)
    {
        return _executeValidated(policyId, msg.sender, target, msg.value, data);
    }

    /// @inheritdoc IPolicyEngine
    /// @dev The signer authorizes (policyId, target, exact calldata, value,
    ///      nonce, deadline). Anyone may relay. `value` is bound to msg.value
    ///      so a relayer cannot change the attached ETH without invalidating
    ///      the signature. Nonce is per-signer and consumed before the call.
    function executeDelegated(
        uint256 policyId,
        address target,
        bytes calldata data,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external payable nonReentrant whenNotPaused returns (bytes memory result) {
        if (block.timestamp > deadline) revert SignatureExpired(deadline);
        if (!_exists(policyId)) revert PolicyNotFound(policyId);

        bytes32 structHash =
            keccak256(abi.encode(EXECUTION_TYPEHASH, policyId, target, keccak256(data), msg.value, nonce, deadline));
        address signer = ECDSA.recoverCalldata(_hashTypedDataV4(structHash), signature);

        if (nonce != _signerNonces[signer]) revert InvalidSignature();
        address expected = _policies[policyId].allowedCaller;
        if (expected != address(0) && signer != expected) revert InvalidSignature();

        _signerNonces[signer] = nonce + 1;

        result = _executeValidated(policyId, signer, target, msg.value, data);
        emit DelegatedExecution(msg.sender, signer, policyId);
    }

    /// @inheritdoc IPolicyEngine
    /// @dev Signer-driven cancellation: jumping the nonce forward invalidates
    ///      every pending delegated intent at or below the previous nonce
    ///      (each signature binds an exact nonce). No role required — it only
    ///      ever affects the caller's own nonce — and it is NOT pause-gated:
    ///      revoking a leaked signature must work during an emergency.
    function invalidateDelegationNonce(uint256 newNonce) external {
        uint256 current = _signerNonces[msg.sender];
        if (newNonce <= current) revert InvalidNonce();
        _signerNonces[msg.sender] = newNonce;
        emit DelegationNonceInvalidated(msg.sender, newNonce);
    }

    /// @inheritdoc IPolicyEngine
    /// @dev ATOMIC: any failing leg reverts the whole batch (no partial
    ///      execution, no silent skips). `sum(values) == msg.value` is enforced
    ///      so ETH cannot be smuggled past per-policy accounting. Repeating the
    ///      same policy twice in one batch fails closed on cooldown/period
    ///      unless the policy explicitly allows it (cooldown == 0 etc.).
    function executeBatch(BatchCall[] calldata calls)
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes[] memory results)
    {
        uint256 n = calls.length;
        if (n == 0) revert EmptyBatch();
        if (n > _maxBatchSize) revert BatchTooLarge(n, _maxBatchSize);

        uint256 total;
        for (uint256 i = 0; i < n; ++i) {
            total += calls[i].value;
        }
        if (total != msg.value) revert BatchValueMismatch(total, msg.value);

        results = new bytes[](n);
        for (uint256 i = 0; i < n; ++i) {
            results[i] =
                _executeValidated(calls[i].policyId, msg.sender, calls[i].target, calls[i].value, calls[i].data);
        }
        emit BatchExecuted(msg.sender, n, total);
    }

    /*//////////////////////////////////////////////////////////////
                           SHARED CORE PATH
    //////////////////////////////////////////////////////////////*/

    /// @dev Single choke point for ALL execution: validate -> precise revert on
    ///      denial -> commit accounting (effects) -> external call (interaction).
    ///      Target failure reverts everything, preserving quota/cooldown.
    function _executeValidated(uint256 policyId, address caller, address target, uint256 value, bytes calldata data)
        internal
        returns (bytes memory result)
    {
        bytes32 reason = _check(policyId, caller, target, value, data);
        if (reason != REASON_OK) _revertWithReason(policyId, reason, caller, target, value, data);

        Policy storage p = _policies[policyId];
        _commitAccounting(p, value);

        // Zero-size output area: the EVM does NOT copy returndata here, so a
        // malicious target cannot force an unbounded memory copy into engine
        // frames. Failure payload is copied separately, bounded
        // (MAX_FAILURE_RETURNDATA); success copies the full returndata
        // deliberately — silently truncating a successful result is worse than
        // letting an oversized return-gas-out the whole atomic call (fail
        // closed, quota/cooldown roll back with the revert).
        // CALL reads its argument region from MEMORY, so the calldata slice is
        // copied first (the same copy Solidity's high-level call performs).
        bytes memory input = data;
        bool ok;
        assembly ("memory-safe") {
            ok := call(gas(), target, value, add(input, 0x20), mload(input), 0, 0)
        }

        if (!ok) {
            // Telemetry for tracing/simulation tooling; rolled back on-chain by
            // the revert below (by design: failures must not consume quota).
            emit PolicyExecutionFailed(policyId, target);
            revert TargetCallFailed(policyId, _failureReturndata());
        }

        assembly ("memory-safe") {
            let size := returndatasize()
            result := mload(0x40)
            mstore(result, size)
            returndatacopy(add(result, 0x20), 0, size)
            mstore(0x40, and(add(add(result, 0x20), add(size, 0x1f)), not(0x1f)))
        }
        emit PolicyExecuted(policyId, caller, target, value);
        return result;
    }

    /// @dev Copies at most `MAX_FAILURE_RETURNDATA` bytes of the pending
    ///      returndata into a fresh bytes (failure path only — bounded bubble
    ///      into `TargetCallFailed`). Must be called with no intervening
    ///      external call, while the target's returndata is still pending.
    function _failureReturndata() internal pure returns (bytes memory out) {
        assembly ("memory-safe") {
            let size := returndatasize()
            if gt(size, MAX_FAILURE_RETURNDATA) { size := MAX_FAILURE_RETURNDATA }
            out := mload(0x40)
            mstore(out, size)
            returndatacopy(add(out, 0x20), 0, size)
            mstore(0x40, and(add(add(out, 0x20), add(size, 0x1f)), not(0x1f)))
        }
    }

    /// @dev Effects before interactions: quota window rollover, spend commit,
    ///      lifetime totals, execution stamp.
    function _commitAccounting(Policy storage p, uint256 value) internal {
        if (p.period > 0) {
            uint64 w = _windowStart(p.period, block.timestamp);
            if (p.periodStart != w) {
                p.periodStart = w;
                p.spentInPeriod = value;
            } else {
                p.spentInPeriod += value;
            }
        }
        p.totalSpent += value;
        p.execCount += 1;
        p.lastExecution = uint64(block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                        VALIDATION (SHARED)
    //////////////////////////////////////////////////////////////*/

    /// @dev Read-only validation shared by execution and `checkPolicy`.
    ///      Order is fail-closed and cheap-checks-first.
    function _check(uint256 policyId, address caller, address target, uint256 value, bytes calldata data)
        internal
        view
        returns (bytes32)
    {
        if (paused()) return REASON_PAUSED;
        if (!_exists(policyId)) return REASON_NOT_FOUND;
        Policy storage p = _policies[policyId];

        if (!p.active) return REASON_DISABLED;
        if (block.timestamp < p.validAfter) return REASON_NOT_STARTED;
        if (p.expiry != 0 && block.timestamp >= p.expiry) return REASON_EXPIRED;
        if (p.allowedCaller != address(0) && caller != p.allowedCaller) return REASON_UNAUTHORIZED;
        if (target != p.target) return REASON_TARGET;

        if (p.selector == bytes4(0)) {
            // wildcard: any calldata (including empty) accepted
        } else {
            if (data.length < 4) return REASON_MALFORMED;
            bytes4 actual;
            assembly ("memory-safe") {
                actual := calldataload(data.offset)
            }
            if (actual != p.selector) return REASON_SELECTOR;
        }

        if (value > p.maxValue) return REASON_VALUE;

        uint256 last = p.lastExecution;
        if (p.cooldown > 0 && last != 0 && block.timestamp < last + p.cooldown) return REASON_COOLDOWN;

        if (p.period > 0) {
            uint64 w = _windowStart(p.period, block.timestamp);
            uint256 spent = (p.periodStart == w) ? p.spentInPeriod : 0;
            if (spent + value > p.periodLimit) return REASON_PERIOD;
        }

        if (p.argAmountCap > 0) {
            uint256 off = p.argOffset;
            if (data.length < off + 32) return REASON_MALFORMED;
            bytes memory m = data;
            uint256 amt;
            assembly ("memory-safe") {
                amt := mload(add(add(m, 32), off))
            }
            if (amt > p.argAmountCap) return REASON_AMOUNT;
        }

        return REASON_OK;
    }

    /// @dev Maps a coarse denial reason to the precise custom error.
    function _revertWithReason(
        uint256 policyId,
        bytes32 reason,
        address caller,
        address target,
        uint256 value,
        bytes calldata data
    ) internal view {
        Policy storage p = _policies[policyId];
        if (reason == REASON_NOT_FOUND) revert PolicyNotFound(policyId);
        if (reason == REASON_DISABLED) revert PolicyNotActive(policyId);
        if (reason == REASON_NOT_STARTED) revert PolicyNotStarted(policyId, p.validAfter);
        if (reason == REASON_EXPIRED) revert PolicyExpired(policyId);
        if (reason == REASON_UNAUTHORIZED) revert UnauthorizedCaller(caller);
        if (reason == REASON_TARGET) revert TargetMismatch(p.target, target);
        if (reason == REASON_SELECTOR) {
            bytes4 actual;
            assembly ("memory-safe") {
                actual := calldataload(data.offset)
            }
            revert SelectorMismatch(p.selector, actual);
        }
        if (reason == REASON_MALFORMED) revert MalformedCalldata();
        if (reason == REASON_VALUE) revert ValueLimitExceeded(value, p.maxValue);
        if (reason == REASON_COOLDOWN) revert CooldownActive(uint256(p.lastExecution) + p.cooldown);
        if (reason == REASON_PERIOD) {
            uint64 w = _windowStart(p.period, block.timestamp);
            uint256 spent = (p.periodStart == w) ? p.spentInPeriod : 0;
            uint256 remaining = p.periodLimit > spent ? p.periodLimit - spent : 0;
            revert PeriodLimitExceeded(value, remaining);
        }
        if (reason == REASON_AMOUNT) {
            bytes memory m = data;
            uint256 off = p.argOffset;
            uint256 amt;
            assembly ("memory-safe") {
                amt := mload(add(add(m, 32), off))
            }
            revert ArgAmountExceeded(amt, p.argAmountCap);
        }
        // Unreachable via entry points today (`whenNotPaused` fires first),
        // but map it correctly so a future entry point without the modifier
        // fails with OZ's canonical pause error, not a generic one.
        if (reason == REASON_PAUSED) revert EnforcedPause();
        revert InvalidPolicyConfig(); // unreachable fail-closed
    }

    /*//////////////////////////////////////////////////////////////
                              READ-ONLY
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IPolicyEngine
    function checkPolicy(uint256 policyId, address caller, address target, uint256 value, bytes calldata data)
        external
        view
        returns (bool allowed, bytes32 reason)
    {
        reason = _check(policyId, caller, target, value, data);
        allowed = (reason == REASON_OK);
    }

    /// @inheritdoc IPolicyEngine
    function getPolicy(uint256 policyId) external view returns (Policy memory policy) {
        if (!_exists(policyId)) revert PolicyNotFound(policyId);
        policy = _policies[policyId];
    }

    /// @notice Batch reader for UIs/indexers (view-only convenience).
    function getPolicies(uint256[] calldata ids) external view returns (Policy[] memory out) {
        out = new Policy[](ids.length);
        for (uint256 i = 0; i < ids.length; ++i) {
            if (!_exists(ids[i])) revert PolicyNotFound(ids[i]);
            out[i] = _policies[ids[i]];
        }
    }

    /// @inheritdoc IPolicyEngine
    function nextPolicyId() external view returns (uint256) {
        return _nextPolicyId;
    }

    /// @inheritdoc IPolicyEngine
    function maxBatchSize() external view returns (uint256) {
        return _maxBatchSize;
    }

    /// @inheritdoc IPolicyEngine
    function nonces(address signer) external view returns (uint256) {
        return _signerNonces[signer];
    }

    /// @inheritdoc IPolicyEngine
    function currentWindowStart(uint64 period) external view returns (uint64) {
        if (period == 0) revert InvalidPolicyConfig();
        return _windowStart(period, block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNAL
    //////////////////////////////////////////////////////////////*/

    function _exists(uint256 policyId) internal view returns (bool) {
        return policyId != 0 && policyId < _nextPolicyId && _policies[policyId].target != address(0);
    }

    /// @dev Full-config event shared by create/update (keeps the PRD-mandated
    ///      `PolicyCreated`/`PolicyUpdated` signatures untouched).
    function _emitConfigUpdated(uint256 policyId, PolicyParams calldata params) internal {
        emit PolicyConfigUpdated(
            policyId,
            params.target,
            params.allowedCaller,
            params.selector,
            params.maxValue,
            params.periodLimit,
            params.period,
            params.cooldown,
            params.validAfter,
            params.expiry,
            params.active,
            params.argAmountCap,
            params.argOffset
        );
    }

    /// @dev Anchored window: floor(now / period) * period. `period > 0` required.
    function _windowStart(uint64 period, uint256 timestamp) internal pure returns (uint64) {
        return uint64((timestamp / period) * period);
    }

    function _validateParams(PolicyParams calldata params) internal view {
        if (params.target == address(0)) revert InvalidPolicyConfig();
        // The engine must never be its own policy target: reaching any state
        // changer would require roles + nonReentrant today, but rejecting here
        // removes the whole self-call hazard class (defense in depth).
        if (params.target == address(this)) revert InvalidPolicyConfig();
        // Quota fields must be both zero (disabled) or both non-zero (enabled):
        // a lone period or lone limit would silently reinterpret old accounting.
        if ((params.period == 0) != (params.periodLimit == 0)) revert InvalidPolicyConfig();
        if (params.validAfter != 0 && params.expiry != 0 && params.validAfter >= params.expiry) {
            revert InvalidPolicyConfig();
        }
        // Amount guard reads a uint256 at `argOffset` inside calldata, which
        // starts with a 4-byte selector: offsets below 4 would constrain the
        // selector itself and are almost certainly a misconfiguration.
        if (params.argAmountCap > 0 && params.argOffset < 4) revert InvalidPolicyConfig();
    }

    /// @dev Computes the EIP-712 digest for a delegated execution (view helper
    ///      for off-chain signing and tests).
    function delegatedDigest(
        uint256 policyId,
        address target,
        bytes calldata data,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32 digest) {
        bytes32 structHash = keccak256(
            abi.encode(EXECUTION_TYPEHASH, policyId, target, keccak256(data), value, nonce, deadline)
        );
        return _hashTypedDataV4(structHash);
    }

    /*//////////////////////////////////////////////////////////////
                       ETH HANDLING (FAIL CLOSED)
    //////////////////////////////////////////////////////////////*/

    /// @notice Direct transfers are rejected: ETH may only arrive via a payable
    ///         execution entry point that is bound to a policy.
    receive() external payable {
        revert DirectEthNotAccepted();
    }

    fallback() external payable {
        revert DirectEthNotAccepted();
    }
}
