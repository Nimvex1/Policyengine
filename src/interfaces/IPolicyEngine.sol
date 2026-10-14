// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IPolicyEngine — stable integration interface for the On-Chain Policy Engine
/// @notice Firewall for smart-contract calls: every execution path validates
///         caller / target / selector / value / quota / cooldown / time window
///         and then forwards the call. Fail closed on any doubt.
interface IPolicyEngine {
    /*//////////////////////////////////////////////////////////////
                              DATA MODEL
    //////////////////////////////////////////////////////////////*/

    /// @notice Stored policy. Accounting fields are engine-managed.
    /// @dev Zero-value meanings (explicit, no silent sentinels):
    ///      - allowedCaller == address(0) => ANY caller may execute (explicit wildcard)
    ///      - selector == bytes4(0)       => ANY selector/calldata may execute (explicit wildcard)
    ///      - maxValue == 0               => only zero-value calls allowed
    ///      - period == 0 AND periodLimit == 0 => no periodic quota (both must be zero together)
    ///      - cooldown == 0               => no cooldown
    ///      - validAfter == 0             => active immediately
    ///      - expiry == 0                 => never expires, otherwise EXCLUSIVE (block.timestamp < expiry)
    ///      - argAmountCap == 0           => no calldata-amount guard
    ///      - lastExecution == 0          => never executed
    ///      Policy IDs start at 1. ID 0 is never valid. Deleted policies read back
    ///      as all-zero and behave as non-existent. IDs are never reused.
    struct Policy {
        address target;
        address allowedCaller;
        uint256 maxValue;
        uint256 periodLimit;
        uint256 spentInPeriod;
        uint256 totalSpent;
        uint256 argAmountCap;
        uint64 period;
        uint64 periodStart;
        uint64 cooldown;
        uint64 lastExecution;
        uint64 validAfter;
        uint64 expiry;
        bytes4 selector;
        bool active;
        uint16 argOffset;
        uint32 version;
        uint32 execCount;
    }

    /// @notice Caller-supplied policy configuration (no accounting fields).
    struct PolicyParams {
        address target;
        address allowedCaller;
        bytes4 selector;
        uint256 maxValue;
        uint256 periodLimit;
        uint64 period;
        uint64 cooldown;
        uint64 validAfter;
        uint64 expiry;
        bool active;
        uint256 argAmountCap;
        uint16 argOffset;
    }

    /// @notice One leg of an atomic batch execution.
    struct BatchCall {
        uint256 policyId;
        address target;
        bytes data;
        uint256 value;
    }

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error PolicyNotFound(uint256 policyId);
    /// @dev Named `PolicyNotActive` (rather than `PolicyDisabled`) because the
    ///      `PolicyDisabled` identifier is taken by the lifecycle event — both
    ///      names appear in the PRD and this keeps the event signature stable.
    error PolicyNotActive(uint256 policyId);
    error UnauthorizedCaller(address caller);
    error TargetMismatch(address expected, address actual);
    error SelectorMismatch(bytes4 expected, bytes4 actual);
    error PolicyNotStarted(uint256 policyId, uint256 startsAt);
    error PolicyExpired(uint256 policyId);
    error ValueLimitExceeded(uint256 requested, uint256 maximum);
    error PeriodLimitExceeded(uint256 requested, uint256 remaining);
    error CooldownActive(uint256 nextAllowedAt);
    error MalformedCalldata();
    error ArgAmountExceeded(uint256 requested, uint256 maximum);
    error TargetCallFailed(uint256 policyId, bytes returnData);
    error BatchTooLarge(uint256 size, uint256 maximum);
    error EmptyBatch();
    /// @dev `expected` is the required sum of leg values; `actual` is the
    ///      `msg.value` the caller attached.
    error BatchValueMismatch(uint256 expected, uint256 actual);
    error SignatureExpired(uint256 deadline);
    error InvalidSignature();
    /// @dev `invalidateDelegationNonce` was called with `newNonce` not greater
    ///      than the signer's current nonce.
    error InvalidNonce();
    error InvalidPolicyConfig();
    error ZeroAddress();
    error DirectEthNotAccepted();
    /// @dev `sweepStuckETH` recipient rejected the ETH transfer.
    error RescueFailed();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event PolicyCreated(uint256 indexed policyId, address indexed caller, address indexed target, bytes4 selector);
    event PolicyUpdated(uint256 indexed policyId);
    /// @notice Full effective configuration after create/update. Indexers use
    ///         this (in addition to the stable `PolicyCreated`/`PolicyUpdated`
    ///         events above) to detect silent redirection of a live policy.
    event PolicyConfigUpdated(
        uint256 indexed policyId,
        address target,
        address allowedCaller,
        bytes4 selector,
        uint256 maxValue,
        uint256 periodLimit,
        uint64 period,
        uint64 cooldown,
        uint64 validAfter,
        uint64 expiry,
        bool active,
        uint256 argAmountCap,
        uint16 argOffset
    );
    event PolicyDisabled(uint256 indexed policyId);
    event PolicyEnabled(uint256 indexed policyId);
    event PolicyDeleted(uint256 indexed policyId);
    event PolicyExecuted(uint256 indexed policyId, address indexed caller, address indexed target, uint256 value);
    /// @notice Emitted (then reverted past) when a target call fails, so failure
    ///         telemetry is visible to tracing/simulation tooling. The canonical
    ///         on-chain signal is `TargetCallFailed`; atomic revert rolls this
    ///         log back on-chain by design so quota/cooldown are never consumed.
    event PolicyExecutionFailed(uint256 indexed policyId, address indexed target);
    event EnginePaused(address indexed account);
    event EngineUnpaused(address indexed account);
    event BatchExecuted(address indexed relayer, uint256 count, uint256 totalValue);
    event DelegatedExecution(address indexed relayer, address indexed signer, uint256 indexed policyId);
    /// @notice Signer advanced their own nonce, invalidating every pending
    ///         delegated signature at or below the previous nonce.
    event DelegationNonceInvalidated(address indexed signer, uint256 newNonce);
    event Rescue(address indexed to, uint256 amount);
    event MaxBatchSizeUpdated(uint256 oldSize, uint256 newSize);

    /*//////////////////////////////////////////////////////////////
                            LIFECYCLE / ADMIN
    //////////////////////////////////////////////////////////////*/

    function createPolicy(PolicyParams calldata params) external returns (uint256 policyId);
    function updatePolicy(uint256 policyId, PolicyParams calldata params) external;
    function setPolicyActive(uint256 policyId, bool active) external;
    function deletePolicy(uint256 policyId) external;
    function setMaxBatchSize(uint256 newSize) external;
    function pause() external;
    function unpause() external;
    function sweepStuckETH(address payable to) external;

    /*//////////////////////////////////////////////////////////////
                               EXECUTION
    //////////////////////////////////////////////////////////////*/

    function execute(uint256 policyId, address target, bytes calldata data)
        external
        payable
        returns (bytes memory result);

    function executeDelegated(
        uint256 policyId,
        address target,
        bytes calldata data,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external payable returns (bytes memory result);

    /// @notice Cancel all pending delegated intents for the caller by jumping
    ///         their own nonce forward. Self-service (no role), allowed while
    ///         paused (cancellation must never be blocked).
    function invalidateDelegationNonce(uint256 newNonce) external;

    function executeBatch(BatchCall[] calldata calls) external payable returns (bytes[] memory results);

    /*//////////////////////////////////////////////////////////////
                              READ-ONLY
    //////////////////////////////////////////////////////////////*/

    /// @notice Simulate an execution. `reason` is a short human-readable code
    ///         ("OK" when allowed). Shares internal validation with execution.
    function checkPolicy(uint256 policyId, address caller, address target, uint256 value, bytes calldata data)
        external
        view
        returns (bool allowed, bytes32 reason);

    function getPolicy(uint256 policyId) external view returns (Policy memory policy);
    function getPolicies(uint256[] calldata ids) external view returns (Policy[] memory out);
    function nextPolicyId() external view returns (uint256);
    function maxBatchSize() external view returns (uint256);
    function nonces(address signer) external view returns (uint256);
    function currentWindowStart(uint64 period) external view returns (uint64);
}
