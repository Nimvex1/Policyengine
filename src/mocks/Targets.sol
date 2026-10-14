// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPolicyEngine} from "../interfaces/IPolicyEngine.sol";

/// @notice Honest target used by tests: payable sink, selector variety,
///         ERC-20-style `transfer(address,uint256)` for amount-guard tests.
contract SimpleTarget {
    uint256 public totalReceived;
    uint256 public calls;

    event Called(address indexed sender, uint256 value, bytes data);

    function ping() external returns (bytes32) {
        calls += 1;
        return keccak256("pong");
    }

    function pay() external payable returns (uint256) {
        calls += 1;
        totalReceived += msg.value;
        emit Called(msg.sender, msg.value, "");
        return msg.value;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        calls += 1;
        emit Called(msg.sender, 0, abi.encode(to, amount));
        return true;
    }

    function boom() external pure {
        revert("boom");
    }

    function echo(bytes calldata b) external payable returns (bytes memory) {
        calls += 1;
        return b;
    }
}

/// @notice Adversarial target: reenters the engine, refunds unexpectedly,
///         reverts, or attempts nested execution under another policy.
contract MaliciousTarget {
    IPolicyEngine public engine;
    uint256 public mode; // 0=benign 1=reenter 2=refund 3=revert 4=nested
    uint256 public attackPolicy;
    bytes public attackData;

    constructor(IPolicyEngine e) {
        engine = e;
    }

    function setReenter(uint256 pid, bytes calldata d) external {
        mode = 1;
        attackPolicy = pid;
        attackData = d;
    }

    function setRefund() external {
        mode = 2;
    }

    function setRevert() external {
        mode = 3;
    }

    function setNested(uint256 pid, bytes calldata d) external {
        mode = 4;
        attackPolicy = pid;
        attackData = d;
    }

    function setBenign() external {
        mode = 0;
    }

    function pay() external payable returns (uint256) {
        if (mode == 1 || mode == 4) {
            engine.execute{value: 0}(attackPolicy, address(this), attackData);
        } else if (mode == 2) {
            // Attempt to push unexpected ETH back into the engine.
            (bool ok,) = payable(msg.sender).call{value: msg.value}("");
            require(ok, "refund failed");
        } else if (mode == 3) {
            revert("malicious boom");
        }
        return msg.value;
    }

    function ping() external returns (bytes32) {
        return keccak256("evil");
    }
}

/// @notice Force-feeds ETH into a target via construction-time selfdestruct
///         (post-Dencun, selfdestruct only transfers in its creation tx).
contract ForceFeeder {
    constructor(address payable to) payable {
        selfdestruct(to);
    }
}

/// @notice Reverts with a 64 KiB payload: exercises the engine's bounded
///         failure-receipt bubble (`TargetCallFailed` caps at
///         `MAX_FAILURE_RETURNDATA`) instead of copying the raw bomb.
contract RevertBomb {
    function fire() external pure {
        assembly ("memory-safe") {
            revert(0, 0x10000)
        }
    }
}

/// @notice Contract with no receive/fallback: rejects plain ETH transfers.
contract EthRejector {}
