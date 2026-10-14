// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {PolicyEngine} from "../src/PolicyEngine.sol";

/// @notice Deploys PolicyEngine; broadcaster becomes bootstrap admin
///         (DEFAULT_ADMIN + POLICY_ADMIN + PAUSER — reassign after deploy).
contract Deploy is Script {
    function run() external returns (PolicyEngine engine) {
        vm.startBroadcast();
        engine = new PolicyEngine(msg.sender);
        vm.stopBroadcast();
    }
}
