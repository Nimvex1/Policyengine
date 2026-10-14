// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PolicyEngine} from "../src/PolicyEngine.sol";
import {IPolicyEngine} from "../src/interfaces/IPolicyEngine.sol";
import {SimpleTarget, ForceFeeder} from "../src/mocks/Targets.sol";

/// @notice Audit confirmation PoCs — each test demonstrates an attempted
///         attack path and asserts the engine fails closed (or behaves
///         as documented). Findings are reported only if an assert proves
///         an invariant violation; here we prove the OPPOSITE (safety).
contract AuditPoC is Test {
    PolicyEngine engine;
    SimpleTarget target;
    address admin = address(this);
    address operator = makeAddr("operator");
    bytes4 PAY = SimpleTarget.pay.selector;

    function setUp() public {
        engine = new PolicyEngine(admin);
        target = new SimpleTarget();
        vm.deal(operator, 100 ether);
        vm.deal(address(this), 100 ether);
    }

    function _p(address t, address c, bytes4 s) internal pure returns (IPolicyEngine.PolicyParams memory) {
        return IPolicyEngine.PolicyParams({
            target: t,
            allowedCaller: c,
            selector: s,
            maxValue: 10 ether,
            periodLimit: 0,
            period: 0,
            cooldown: 0,
            validAfter: 0,
            expiry: 0,
            active: true,
            argAmountCap: 0,
            argOffset: 0
        });
    }

    /// PATH 1: POLICY_ADMIN points a policy at the engine itself — the engine
    /// rejects itself as a policy target outright at config time, so no policy
    /// (even one authorizing pause/execute/sweep) can ever be created, let
    /// alone pivoted to a privileged self-call. Defense in depth on top of the
    /// existing roles + nonReentrant guards.
    function test_PoC_SelfTarget_PolicyCreationRejected() public {
        new ForceFeeder{value: 1 ether}(payable(address(engine)));

        vm.expectRevert(IPolicyEngine.InvalidPolicyConfig.selector);
        engine.createPolicy(_p(address(engine), operator, PolicyEngine.pause.selector));

        vm.expectRevert(IPolicyEngine.InvalidPolicyConfig.selector);
        engine.createPolicy(_p(address(engine), operator, PolicyEngine.execute.selector));

        vm.expectRevert(IPolicyEngine.InvalidPolicyConfig.selector);
        engine.createPolicy(_p(address(engine), operator, PolicyEngine.sweepStuckETH.selector));

        assertEq(engine.nextPolicyId(), 1); // nothing was created
        assertFalse(engine.paused()); // pause unreachable via a self policy
        assertEq(address(engine).balance, 1 ether); // force-fed funds untouched
    }

    /// PATH 2: Force-fed ETH must never be forwardable by execute paths —
    /// execution value is always exactly the caller's msg.value, never the
    /// contract balance.
    function test_PoC_ForceFedEth_NotForwardableByExecution() public {
        new ForceFeeder{value: 5 ether}(payable(address(engine)));
        uint256 id = engine.createPolicy(_p(address(target), operator, PAY));
        // operator executes with their own 1 ETH: target must receive exactly
        // 1 ETH; the force-fed 5 ETH must remain.
        vm.prank(operator);
        engine.execute{value: 1 ether}(id, address(target), abi.encodeWithSelector(PAY));
        assertEq(target.totalReceived(), 1 ether);
        assertEq(address(engine).balance, 5 ether); // force-fed balance intact
        // Only DEFAULT_ADMIN sweep can move it (tested separately).
    }

    /// PATH 3: Batch target spoof — leg target different from policy target.
    function test_PoC_Batch_TargetSpoof_RevertsAtomically() public {
        uint256 id = engine.createPolicy(_p(address(target), operator, PAY));
        SimpleTarget other = new SimpleTarget();
        IPolicyEngine.BatchCall[] memory calls = new IPolicyEngine.BatchCall[](1);
        calls[0] = IPolicyEngine.BatchCall({
            policyId: id, target: address(other), data: abi.encodeWithSelector(PAY), value: 0
        });
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.TargetMismatch.selector, address(target), address(other)));
        engine.executeBatch(calls);
        assertEq(other.totalReceived(), 0);
    }

    /// PATH 4: Same policy twice in one batch with cooldown > 0 —
    /// second leg must fail closed (no quota/cooldown bypass via batching).
    function test_PoC_Batch_SamePolicyCooldown_NoBypass() public {
        IPolicyEngine.PolicyParams memory ps = _p(address(target), operator, PAY);
        ps.cooldown = 1 hours;
        uint256 id = engine.createPolicy(ps);
        IPolicyEngine.BatchCall[] memory calls = new IPolicyEngine.BatchCall[](2);
        calls[0] = IPolicyEngine.BatchCall({
            policyId: id, target: address(target), data: abi.encodeWithSelector(PAY), value: 0
        });
        calls[1] = IPolicyEngine.BatchCall({
            policyId: id, target: address(target), data: abi.encodeWithSelector(PAY), value: 0
        });
        vm.prank(operator);
        vm.expectRevert(); // CooldownActive on leg 2, whole batch reverts
        engine.executeBatch(calls);
        assertEq(engine.getPolicy(id).execCount, 0); // leg 1 state also rolled back
    }

    /// PATH 5: Batch sum(values) == msg.value — no ETH smuggle past accounting.
    function test_PoC_Batch_EthSmuggle_Reverts() public {
        uint256 id = engine.createPolicy(_p(address(target), operator, PAY));
        IPolicyEngine.BatchCall[] memory calls = new IPolicyEngine.BatchCall[](1);
        calls[0] = IPolicyEngine.BatchCall({
            policyId: id, target: address(target), data: abi.encodeWithSelector(PAY), value: 0
        });
        // send 1 ETH with a 0-value leg: engine would otherwise pocket it
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.BatchValueMismatch.selector, 0, 1 ether));
        engine.executeBatch{value: 1 ether}(calls);
        assertEq(address(engine).balance, 0);
    }

    /// PATH 6: executeDelegated on a WILDCARD-caller policy accepts any signer,
    /// but that is identical in power to direct execute (also unrestricted).
    /// Asserts documented consistency, not a privilege gain.
    function test_PoC_DelegatedWildcard_ConsistentWithDirectPath() public {
        IPolicyEngine.PolicyParams memory ps = _p(address(target), address(0), PAY); // wildcard caller
        uint256 id = engine.createPolicy(ps);
        uint256 key = 0xB0B;
        address sgn = vm.addr(key);
        bytes memory d = abi.encodeWithSelector(PAY);
        uint256 deadline = block.timestamp + 1;
        bytes32 dig = engine.delegatedDigest(id, address(target), d, 0, 0, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, dig);
        vm.deal(sgn, 1 ether);
        engine.executeDelegated(id, address(target), d, 0, deadline, abi.encodePacked(r, s, v));
        // direct path grants the same unrestricted access — no escalation delta
        vm.prank(makeAddr("anyone"));
        engine.execute(id, address(target), d);
        assertEq(engine.getPolicy(id).execCount, 2);
    }

    /// PATH 7: RESTRICTED-caller policy — delegated execution by a
    /// non-allowed signer must fail even with a valid self-signature.
    function test_PoC_Delegated_RestrictedPolicy_ForeignSignerRejected() public {
        IPolicyEngine.PolicyParams memory ps = _p(address(target), operator, PAY);
        uint256 id = engine.createPolicy(ps);
        uint256 key = 0xBAD;
        address sgn = vm.addr(key);
        bytes memory d = abi.encodeWithSelector(PAY);
        uint256 deadline = block.timestamp + 1;
        bytes32 dig = engine.delegatedDigest(id, address(target), d, 0, 0, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, dig);
        vm.prank(makeAddr("relayer"));
        vm.expectRevert(IPolicyEngine.InvalidSignature.selector);
        engine.executeDelegated(id, address(target), d, 0, deadline, abi.encodePacked(r, s, v));
    }

    /// PATH 8: Signature binds msg.value — relayer cannot change attached ETH.
    /// Policy allows the signer as caller so the ONLY failing check is value binding.
    function test_PoC_Delegated_ValueSubstitution_Rejected() public {
        uint256 key = 0xA11CE;
        address sgn = vm.addr(key);
        IPolicyEngine.PolicyParams memory ps = _p(address(target), sgn, PAY);
        uint256 id = engine.createPolicy(ps);
        bytes memory d = abi.encodeWithSelector(PAY);
        uint256 deadline = block.timestamp + 1;
        bytes32 dig = engine.delegatedDigest(id, address(target), d, 1 ether, 0, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, dig);
        bytes memory sig = abi.encodePacked(r, s, v);
        // relayer attaches 2 ETH instead of signed 1 ETH -> different digest
        vm.deal(makeAddr("relayer"), 2 ether);
        vm.prank(makeAddr("relayer"));
        vm.expectRevert(IPolicyEngine.InvalidSignature.selector);
        engine.executeDelegated{value: 2 ether}(id, address(target), d, 0, deadline, sig);
        // sanity: correct value (1 ETH) with same signature succeeds
        vm.deal(makeAddr("relayer"), 1 ether);
        vm.prank(makeAddr("relayer"));
        engine.executeDelegated{value: 1 ether}(id, address(target), d, 0, deadline, sig);
        assertEq(target.totalReceived(), 1 ether);
    }

    /// PATH 9: Policy deleted mid-flight — pending delegated sig dies with it.
    function test_PoC_Delegated_AfterDelete_Rejected() public {
        IPolicyEngine.PolicyParams memory ps = _p(address(target), operator, PAY);
        uint256 id = engine.createPolicy(ps);
        bytes memory d = abi.encodeWithSelector(PAY);
        uint256 deadline = block.timestamp + 1;
        bytes32 dig = engine.delegatedDigest(id, address(target), d, 0, 0, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xA11CE, dig);
        engine.deletePolicy(id);
        vm.prank(makeAddr("relayer"));
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyNotFound.selector, id));
        engine.executeDelegated(id, address(target), d, 0, deadline, abi.encodePacked(r, s, v));
    }
}
