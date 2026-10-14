// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {PolicyEngine} from "../src/PolicyEngine.sol";
import {IPolicyEngine} from "../src/interfaces/IPolicyEngine.sol";
import {SimpleTarget, MaliciousTarget, ForceFeeder, RevertBomb, EthRejector} from "../src/mocks/Targets.sol";

contract PolicyEngineTest is Test {
    PolicyEngine internal engine;
    SimpleTarget internal target;
    MaliciousTarget internal evil;

    address internal admin = address(this);
    address internal operator = makeAddr("operator");
    address internal stranger = makeAddr("stranger");
    address internal relayer = makeAddr("relayer");

    uint256 internal signerKey = 0xA11CE;
    address internal signer;

    bytes4 internal constant PAY_SEL = SimpleTarget.pay.selector;
    bytes4 internal constant PING_SEL = SimpleTarget.ping.selector;

    function setUp() public {
        signer = vm.addr(signerKey);
        engine = new PolicyEngine(admin);
        target = new SimpleTarget();
        evil = new MaliciousTarget(IPolicyEngine(address(engine)));
        vm.deal(operator, 100 ether);
        vm.deal(stranger, 100 ether);
        vm.deal(relayer, 100 ether);
        vm.deal(address(this), 1000 ether);
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    function _params(address target_, address caller_, bytes4 sel)
        internal
        pure
        returns (IPolicyEngine.PolicyParams memory)
    {
        return IPolicyEngine.PolicyParams({
            target: target_,
            allowedCaller: caller_,
            selector: sel,
            maxValue: 2 ether,
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

    function _createBasic() internal returns (uint256 id) {
        id = engine.createPolicy(_params(address(target), operator, PAY_SEL));
    }

    /// @dev External wrapper so fuzz tests can try/catch executions.
    function extExec(uint256 pid, address tgt, bytes calldata d) external payable returns (bytes memory) {
        return engine.execute{value: msg.value}(pid, tgt, d);
    }

    /*//////////////////////////////////////////////////////////////
                           LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CreatePolicy_AssignsIdAndStores() public {
        uint256 id = engine.createPolicy(_params(address(target), operator, PAY_SEL));
        assertEq(id, 1);
        IPolicyEngine.Policy memory p = engine.getPolicy(id);
        assertEq(p.target, address(target));
        assertEq(p.allowedCaller, operator);
        assertEq(p.selector, PAY_SEL);
        assertEq(p.maxValue, 2 ether);
        assertTrue(p.active);
        assertEq(p.version, 1);
        assertEq(engine.nextPolicyId(), 2);
    }

    function test_CreatePolicy_RevertsOnZeroTarget() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(0), operator, PAY_SEL);
        vm.expectRevert(IPolicyEngine.InvalidPolicyConfig.selector);
        engine.createPolicy(ps);
    }

    function test_CreatePolicy_RevertsOnLonePeriod() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, PAY_SEL);
        ps.period = 1 days; // periodLimit left 0
        vm.expectRevert(IPolicyEngine.InvalidPolicyConfig.selector);
        engine.createPolicy(ps);
    }

    function test_CreatePolicy_RevertsOnLoneLimit() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, PAY_SEL);
        ps.periodLimit = 1 ether; // period left 0
        vm.expectRevert(IPolicyEngine.InvalidPolicyConfig.selector);
        engine.createPolicy(ps);
    }

    function test_CreatePolicy_RevertsOnBadTimeRange() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, PAY_SEL);
        ps.validAfter = 200;
        ps.expiry = 100;
        vm.expectRevert(IPolicyEngine.InvalidPolicyConfig.selector);
        engine.createPolicy(ps);
    }

    function test_CreatePolicy_RevertsForNonAdmin() public {
        vm.prank(stranger);
        vm.expectRevert();
        engine.createPolicy(_params(address(target), operator, PAY_SEL));
    }

    function test_UpdatePolicy_ResetsSpentKeepsCooldown() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, PAY_SEL);
        ps.period = 1 days;
        ps.periodLimit = 10 ether;
        ps.cooldown = 1 hours;
        uint256 id = engine.createPolicy(ps);

        vm.prank(operator);
        engine.execute{value: 1 ether}(id, address(target), abi.encodeWithSelector(PAY_SEL));
        assertEq(engine.getPolicy(id).spentInPeriod, 1 ether);

        ps.maxValue = 5 ether;
        engine.updatePolicy(id, ps);
        IPolicyEngine.Policy memory p = engine.getPolicy(id);
        assertEq(p.spentInPeriod, 0); // reset, never reinterpreted
        assertEq(p.version, 2);
        assertEq(p.maxValue, 5 ether);
        // lastExecution preserved -> cooldown still enforced
        assertTrue(p.lastExecution != 0);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.CooldownActive.selector, p.lastExecution + 3600));
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));
    }

    function test_DisableEnable_BlocksAndRestores() public {
        uint256 id = _createBasic();
        engine.setPolicyActive(id, false);
        assertFalse(engine.getPolicy(id).active);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyNotActive.selector, id));
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));
        engine.setPolicyActive(id, true);
        vm.prank(operator);
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));
    }

    function test_DeletePolicy_NeverReused() public {
        uint256 id1 = _createBasic();
        engine.deletePolicy(id1);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyNotFound.selector, id1));
        engine.getPolicy(id1);
        uint256 id2 = _createBasic();
        assertEq(id2, 2); // monotonic, no reuse
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyNotFound.selector, id1));
        engine.execute{value: 0}(id1, address(target), abi.encodeWithSelector(PAY_SEL));
    }

    /*//////////////////////////////////////////////////////////////
                           MATCHING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Execute_Success_ForwardsValueAndReturndata() public {
        uint256 id = _createBasic();
        vm.prank(operator);
        bytes memory ret = engine.execute{value: 1 ether}(id, address(target), abi.encodeWithSelector(PAY_SEL));
        assertEq(abi.decode(ret, (uint256)), 1 ether);
        assertEq(target.totalReceived(), 1 ether);
        IPolicyEngine.Policy memory p = engine.getPolicy(id);
        assertEq(p.execCount, 1);
        assertEq(p.totalSpent, 1 ether);
    }

    function test_Execute_RevertsForWrongCaller() public {
        uint256 id = _createBasic();
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.UnauthorizedCaller.selector, stranger));
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));
    }

    function test_Execute_RevertsForWrongTarget() public {
        uint256 id = _createBasic();
        address other = address(evil);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.TargetMismatch.selector, address(target), other));
        engine.execute{value: 0}(id, other, abi.encodeWithSelector(PAY_SEL));
    }

    function test_Execute_RevertsForWrongSelector() public {
        uint256 id = _createBasic();
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.SelectorMismatch.selector, PAY_SEL, PING_SEL));
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PING_SEL));
    }

    function test_Execute_RevertsForUnknownPolicy() public {
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyNotFound.selector, 999));
        engine.execute{value: 0}(999, address(target), abi.encodeWithSelector(PAY_SEL));
    }

    function test_Execute_RevertsOnMalformedCalldata() public {
        uint256 id = _createBasic();
        vm.prank(operator);
        vm.expectRevert(IPolicyEngine.MalformedCalldata.selector);
        engine.execute{value: 0}(id, address(target), hex"12");
    }

    function test_WildcardCaller_AllowsAnyone() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), address(0), PAY_SEL);
        uint256 id = engine.createPolicy(ps);
        vm.prank(stranger);
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));
    }

    function test_WildcardSelector_AllowsAnyCalldata() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, bytes4(0));
        uint256 id = engine.createPolicy(ps);
        vm.prank(operator);
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PING_SEL));
        vm.prank(operator);
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));
        // Policy-level simulation also approves empty calldata; whether the
        // TARGET accepts it is the target's own business (here it reverts, and
        // the engine atomically reverts without consuming accounting).
        (bool allowed,) = engine.checkPolicy(id, operator, address(target), 0, hex"");
        assertTrue(allowed);
        vm.prank(operator);
        vm.expectRevert();
        engine.execute{value: 0}(id, address(target), hex"");
        assertEq(engine.getPolicy(id).execCount, 2);
    }

    /*//////////////////////////////////////////////////////////////
                        VALUE / QUOTA / TIME
    //////////////////////////////////////////////////////////////*/

    function test_ValueLimit_AtLimitOkAboveReverts() public {
        uint256 id = _createBasic(); // maxValue 2 ether
        vm.prank(operator);
        engine.execute{value: 2 ether}(id, address(target), abi.encodeWithSelector(PAY_SEL));
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.ValueLimitExceeded.selector, 2 ether + 1, 2 ether));
        engine.execute{value: 2 ether + 1}(id, address(target), abi.encodeWithSelector(PAY_SEL));
    }

    function test_PeriodQuota_EnforcedAndRollover() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, PAY_SEL);
        ps.maxValue = 10 ether;
        ps.period = 1 days;
        ps.periodLimit = 10 ether;
        uint256 id = engine.createPolicy(ps);

        vm.prank(operator);
        engine.execute{value: 6 ether}(id, address(target), abi.encodeWithSelector(PAY_SEL));
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PeriodLimitExceeded.selector, 5 ether, 4 ether));
        engine.execute{value: 5 ether}(id, address(target), abi.encodeWithSelector(PAY_SEL));

        // Anchored window rollover frees quota.
        uint64 w = engine.currentWindowStart(1 days);
        vm.warp(uint256(w) + 1 days + 1);
        vm.prank(operator);
        engine.execute{value: 5 ether}(id, address(target), abi.encodeWithSelector(PAY_SEL));
        assertEq(engine.getPolicy(id).spentInPeriod, 5 ether);
    }

    function test_Cooldown_BlocksEarlyAllowsLate() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, PAY_SEL);
        ps.cooldown = 1 hours;
        uint256 id = engine.createPolicy(ps);

        vm.prank(operator);
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));
        uint256 last = engine.getPolicy(id).lastExecution;
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.CooldownActive.selector, last + 3600));
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));
        vm.warp(last + 3600);
        vm.prank(operator);
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));
    }

    function test_TimeValidity_ValidAfterAndExpiry() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, PAY_SEL);
        ps.validAfter = uint64(block.timestamp + 100);
        ps.expiry = uint64(block.timestamp + 1000);
        uint256 id = engine.createPolicy(ps);

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(IPolicyEngine.PolicyNotStarted.selector, id, uint64(block.timestamp + 100))
        );
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));

        vm.warp(block.timestamp + 100);
        vm.prank(operator);
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));

        vm.warp(block.timestamp + 900); // exactly at expiry -> exclusive, expired
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyExpired.selector, id));
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));
    }

    /*//////////////////////////////////////////////////////////////
                         ARG AMOUNT GUARD
    //////////////////////////////////////////////////////////////*/

    function test_ArgAmountCap_TreasuryStyle() public {
        // transfer(address,uint256): amount lives at calldata offset 4 + 32 = 36.
        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, SimpleTarget.transfer.selector);
        ps.maxValue = 0;
        ps.argAmountCap = 1000;
        ps.argOffset = 36;
        uint256 id = engine.createPolicy(ps);

        vm.prank(operator);
        engine.execute{value: 0}(id, address(target), abi.encodeCall(SimpleTarget.transfer, (operator, 1000)));
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.ArgAmountExceeded.selector, 1001, 1000));
        engine.execute{value: 0}(id, address(target), abi.encodeCall(SimpleTarget.transfer, (operator, 1001)));
    }

    /*//////////////////////////////////////////////////////////////
                            PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Pause_BlocksAllExecutionKeepsAdminAndViews() public {
        uint256 id = _createBasic();
        engine.pause();

        vm.prank(operator);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));

        vm.prank(operator);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        IPolicyEngine.BatchCall[] memory calls = new IPolicyEngine.BatchCall[](1);
        calls[0] = IPolicyEngine.BatchCall({
            policyId: id, target: address(target), data: abi.encodeWithSelector(PAY_SEL), value: 0
        });
        engine.executeBatch(calls);

        // Simulation keeps working and reports PAUSED.
        (bool allowed, bytes32 reason) =
            engine.checkPolicy(id, operator, address(target), 0, abi.encodeWithSelector(PAY_SEL));
        assertFalse(allowed);
        assertEq(reason, bytes32("PAUSED"));

        // Admin lifecycle still available during emergency.
        uint256 id2 = engine.createPolicy(_params(address(target), operator, PAY_SEL));
        assertEq(id2, 2);

        engine.unpause();
        vm.prank(operator);
        engine.execute{value: 0}(id, address(target), abi.encodeWithSelector(PAY_SEL));
    }

    function test_Pause_RevertsForNonPauser() public {
        vm.prank(stranger);
        vm.expectRevert();
        engine.pause();
    }

    /*//////////////////////////////////////////////////////////////
                         SIMULATION PARITY
    //////////////////////////////////////////////////////////////*/

    function test_CheckPolicy_MatchesExecution() public {
        uint256 id = _createBasic();
        bytes memory good = abi.encodeWithSelector(PAY_SEL);
        (bool ok,) = engine.checkPolicy(id, operator, address(target), 1 ether, good);
        assertTrue(ok);
        (bool bad,) = engine.checkPolicy(id, stranger, address(target), 1 ether, good);
        assertFalse(bad);
        (bool over,) = engine.checkPolicy(id, operator, address(target), 3 ether, good);
        assertFalse(over);
    }

    /*//////////////////////////////////////////////////////////////
                         BATCH EXECUTION
    //////////////////////////////////////////////////////////////*/

    function test_Batch_AtomicSuccess() public {
        uint256 id = _createBasic();
        IPolicyEngine.BatchCall[] memory calls = new IPolicyEngine.BatchCall[](2);
        calls[0] = IPolicyEngine.BatchCall({
            policyId: id, target: address(target), data: abi.encodeWithSelector(PAY_SEL), value: 1 ether
        });
        calls[1] = IPolicyEngine.BatchCall({
            policyId: id, target: address(target), data: abi.encodeWithSelector(PAY_SEL), value: 1 ether
        });
        vm.prank(operator);
        bytes[] memory rets = engine.executeBatch{value: 2 ether}(calls);
        assertEq(rets.length, 2);
        assertEq(target.totalReceived(), 2 ether);
    }

    function test_Batch_OneInvalidRevertsAll() public {
        uint256 id = _createBasic();
        IPolicyEngine.BatchCall[] memory calls = new IPolicyEngine.BatchCall[](2);
        calls[0] = IPolicyEngine.BatchCall({
            policyId: id, target: address(target), data: abi.encodeWithSelector(PAY_SEL), value: 1 ether
        });
        calls[1] = IPolicyEngine.BatchCall({
            policyId: id, target: address(evil), data: abi.encodeWithSelector(PAY_SEL), value: 0
        });
        vm.prank(operator);
        vm.expectRevert();
        engine.executeBatch{value: 1 ether}(calls);
        assertEq(engine.getPolicy(id).execCount, 0); // no partial state
        assertEq(target.totalReceived(), 0);
    }

    function test_Batch_ValueMismatchReverts() public {
        uint256 id = _createBasic();
        IPolicyEngine.BatchCall[] memory calls = new IPolicyEngine.BatchCall[](1);
        calls[0] = IPolicyEngine.BatchCall({
            policyId: id, target: address(target), data: abi.encodeWithSelector(PAY_SEL), value: 1 ether
        });
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.BatchValueMismatch.selector, 1 ether, 0));
        engine.executeBatch{value: 0}(calls);
    }

    function test_Batch_TooLargeReverts() public {
        engine.setMaxBatchSize(1);
        uint256 id = _createBasic();
        IPolicyEngine.BatchCall[] memory calls = new IPolicyEngine.BatchCall[](2);
        calls[0] = IPolicyEngine.BatchCall({
            policyId: id, target: address(target), data: abi.encodeWithSelector(PAY_SEL), value: 0
        });
        calls[1] = IPolicyEngine.BatchCall({
            policyId: id, target: address(target), data: abi.encodeWithSelector(PAY_SEL), value: 0
        });
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.BatchTooLarge.selector, 2, 1));
        engine.executeBatch(calls);
    }

    /*//////////////////////////////////////////////////////////////
                         EIP-712 DELEGATION
    //////////////////////////////////////////////////////////////*/

    function _sign(uint256 pid, address tgt, bytes memory d, uint256 value, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes memory sig)
    {
        bytes32 digest = engine.delegatedDigest(pid, tgt, d, value, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        sig = abi.encodePacked(r, s, v);
    }

    function test_Delegated_SuccessViaRelayer() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), signer, PAY_SEL);
        uint256 id = engine.createPolicy(ps);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory d = abi.encodeWithSelector(PAY_SEL);
        bytes memory sig = _sign(id, address(target), d, 1 ether, 0, deadline);

        vm.prank(relayer);
        engine.executeDelegated{value: 1 ether}(id, address(target), d, 0, deadline, sig);
        assertEq(target.totalReceived(), 1 ether);
        assertEq(engine.nonces(signer), 1);
    }

    function test_Delegated_ReplayReverts() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), signer, PAY_SEL);
        uint256 id = engine.createPolicy(ps);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory d = abi.encodeWithSelector(PAY_SEL);
        bytes memory sig = _sign(id, address(target), d, 0, 0, deadline);

        vm.prank(relayer);
        engine.executeDelegated(id, address(target), d, 0, deadline, sig);
        vm.prank(relayer);
        vm.expectRevert(IPolicyEngine.InvalidSignature.selector);
        engine.executeDelegated(id, address(target), d, 0, deadline, sig);
    }

    function test_Delegated_AlteredCalldataReverts() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), signer, PAY_SEL);
        uint256 id = engine.createPolicy(ps);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _sign(id, address(target), abi.encodeWithSelector(PAY_SEL), 0, 0, deadline);
        vm.prank(relayer);
        vm.expectRevert(IPolicyEngine.InvalidSignature.selector);
        engine.executeDelegated(id, address(target), abi.encodeWithSelector(PING_SEL), 0, deadline, sig);
    }

    function test_Delegated_ExpiredReverts() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), signer, PAY_SEL);
        uint256 id = engine.createPolicy(ps);
        uint256 deadline = block.timestamp - 1;
        bytes memory d = abi.encodeWithSelector(PAY_SEL);
        bytes memory sig = _sign(id, address(target), d, 0, 0, deadline);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.SignatureExpired.selector, deadline));
        engine.executeDelegated(id, address(target), d, 0, deadline, sig);
    }

    /*//////////////////////////////////////////////////////////////
                        ADVERSARIAL TARGETS
    //////////////////////////////////////////////////////////////*/

    function test_Malicious_ReenterFailsAtomically() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(evil), operator, MaliciousTarget.pay.selector);
        uint256 id = engine.createPolicy(ps);
        evil.setReenter(id, abi.encodeWithSelector(MaliciousTarget.pay.selector));

        vm.prank(operator);
        vm.expectRevert();
        engine.execute{value: 0}(id, address(evil), abi.encodeWithSelector(MaliciousTarget.pay.selector));

        IPolicyEngine.Policy memory p = engine.getPolicy(id);
        assertEq(p.execCount, 0);
        assertEq(p.spentInPeriod, 0);
    }

    function test_Malicious_NestedPolicyFails() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(evil), operator, MaliciousTarget.pay.selector);
        uint256 id1 = engine.createPolicy(ps);
        uint256 id2 = engine.createPolicy(ps);
        evil.setNested(id2, abi.encodeWithSelector(MaliciousTarget.pay.selector));

        vm.prank(operator);
        vm.expectRevert();
        engine.execute{value: 0}(id1, address(evil), abi.encodeWithSelector(MaliciousTarget.pay.selector));
        assertEq(engine.getPolicy(id1).execCount, 0);
        assertEq(engine.getPolicy(id2).execCount, 0);
    }

    function test_Malicious_RefundFailsSafely() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(evil), operator, MaliciousTarget.pay.selector);
        ps.maxValue = 10 ether;
        uint256 id = engine.createPolicy(ps);
        evil.setRefund();

        vm.prank(operator);
        vm.expectRevert();
        engine.execute{value: 1 ether}(id, address(evil), abi.encodeWithSelector(MaliciousTarget.pay.selector));
        assertEq(engine.getPolicy(id).execCount, 0);
    }

    function test_RevertingTarget_ConsumesNoQuota() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, SimpleTarget.boom.selector);
        ps.period = 1 days;
        ps.periodLimit = 10 ether;
        ps.maxValue = 10 ether;
        uint256 id = engine.createPolicy(ps);

        vm.prank(operator);
        vm.expectRevert();
        engine.execute{value: 1 ether}(id, address(target), abi.encodeWithSelector(SimpleTarget.boom.selector));
        IPolicyEngine.Policy memory p = engine.getPolicy(id);
        assertEq(p.spentInPeriod, 0);
        assertEq(p.execCount, 0);
    }

    /*//////////////////////////////////////////////////////////////
                           ETH HANDLING
    //////////////////////////////////////////////////////////////*/

    function test_DirectEth_Reverts() public {
        (bool ok,) = address(engine).call{value: 1 ether}("");
        assertFalse(ok);
    }

    function test_Sweep_RecoversForceFedEth() public {
        new ForceFeeder{value: 1 ether}(payable(address(engine)));
        assertEq(address(engine).balance, 1 ether);
        address payable dest = payable(makeAddr("dest"));
        engine.sweepStuckETH(dest);
        assertEq(dest.balance, 1 ether);
        assertEq(address(engine).balance, 0);
    }

    /*//////////////////////////////////////////////////////////////
                              FUZZ
    //////////////////////////////////////////////////////////////*/

    function testFuzz_ValueLimit(uint256 value) public {
        value = bound(value, 0, 4 ether);
        uint256 id = _createBasic();
        vm.deal(operator, value);
        vm.prank(operator);
        if (value <= 2 ether) {
            engine.execute{value: value}(id, address(target), abi.encodeWithSelector(PAY_SEL));
        } else {
            vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.ValueLimitExceeded.selector, value, 2 ether));
            engine.execute{value: value}(id, address(target), abi.encodeWithSelector(PAY_SEL));
        }
    }

    /// @notice Stateful fuzz: quota is never exceeded across windows and
    ///         failures never consume accounting.
    function testFuzz_QuotaInvariant(uint256[] memory amounts, uint256 limit) public {
        vm.assume(amounts.length > 0 && amounts.length <= 8);
        limit = bound(limit, 1 ether, 20 ether);
        uint256 id = _createQuotaPolicy(limit);

        bytes memory d = abi.encodeWithSelector(PAY_SEL);
        uint256 modelSpent; // per-window spend (quota model)
        uint256 modelTotal; // lifetime spend (receipt model)
        uint64 modelWindow = engine.currentWindowStart(1 days);

        for (uint256 i = 0; i < amounts.length; ++i) {
            if (i == amounts.length / 2) {
                vm.warp(block.timestamp + 1 days + 1); // force rollover mid-run
                modelWindow = engine.currentWindowStart(1 days);
                modelSpent = 0;
            }
            uint256 v = bound(amounts[i], 0, 2 * limit);
            vm.deal(address(this), v);
            (modelSpent, modelTotal) = _quotaStep(id, d, v, limit, modelWindow, modelSpent, modelTotal);
        }
        assertEq(target.totalReceived(), modelTotal);
    }

    /// @dev Creates the quota policy for the invariant fuzz. Fuzz executions
    ///      run as address(this) (via extExec), so the policy authorizes the
    ///      test contract rather than `operator`.
    function _createQuotaPolicy(uint256 limit) internal returns (uint256 id) {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), address(this), PAY_SEL);
        ps.maxValue = limit;
        ps.period = 1 days;
        ps.periodLimit = limit;
        id = engine.createPolicy(ps);
    }

    /// @dev One fuzz step: simulation must agree with execution, on-chain
    ///      accounting must track the model, quota must never be exceeded.
    function _quotaStep(
        uint256 id,
        bytes memory d,
        uint256 v,
        uint256 limit,
        uint64 modelWindow,
        uint256 modelSpent,
        uint256 modelTotal
    ) internal returns (uint256, uint256) {
        (bool allowed,) = engine.checkPolicy(id, address(this), address(target), v, d);
        bool shouldAllow = (v <= limit) && (modelSpent + v <= limit);
        assertEq(allowed, shouldAllow, "simulation mismatch");
        try this.extExec{value: v}(id, address(target), d) {
            assertTrue(shouldAllow, "execution allowed but model denied");
            modelSpent += v;
            modelTotal += v;
        } catch {
            assertFalse(shouldAllow, "execution denied but model allowed");
        }
        IPolicyEngine.Policy memory p = engine.getPolicy(id);
        uint256 onchain = (p.periodStart == modelWindow) ? p.spentInPeriod : 0;
        assertEq(onchain, modelSpent, "accounting drift");
        assertLe(onchain, limit, "quota exceeded");
        return (modelSpent, modelTotal);
    }

    /*//////////////////////////////////////////////////////////////
                  COVERAGE GAPS & HARDENING (review follow-up)
    //////////////////////////////////////////////////////////////*/

    function test_CreatePolicy_RejectsSelfTarget() public {
        vm.expectRevert(IPolicyEngine.InvalidPolicyConfig.selector);
        engine.createPolicy(_params(address(engine), operator, PAY_SEL));
        assertEq(engine.nextPolicyId(), 1); // nothing created
    }

    function test_UpdatePolicy_RejectsSelfTarget() public {
        uint256 id = _createBasic();
        IPolicyEngine.PolicyParams memory ps = _params(address(engine), operator, PAY_SEL);
        vm.expectRevert(IPolicyEngine.InvalidPolicyConfig.selector);
        engine.updatePolicy(id, ps);
        assertEq(engine.getPolicy(id).target, address(target)); // untouched
    }

    function test_SetMaxBatchSize_RevertsInvalidAndUnauthorized() public {
        uint256 hardCap = engine.MAX_BATCH_HARD_CAP();
        vm.expectRevert(IPolicyEngine.InvalidPolicyConfig.selector);
        engine.setMaxBatchSize(0);
        vm.expectRevert(IPolicyEngine.InvalidPolicyConfig.selector);
        engine.setMaxBatchSize(hardCap + 1);
        vm.prank(stranger);
        vm.expectRevert();
        engine.setMaxBatchSize(5);
        assertEq(engine.maxBatchSize(), 10); // unchanged
        engine.setMaxBatchSize(hardCap);
        assertEq(engine.maxBatchSize(), hardCap);
    }

    function test_Sweep_RevertsZeroAddressAndUnauthorized() public {
        vm.expectRevert(IPolicyEngine.ZeroAddress.selector);
        engine.sweepStuckETH(payable(address(0)));
        vm.prank(stranger);
        vm.expectRevert();
        engine.sweepStuckETH(payable(operator));
    }

    function test_Sweep_ReportsRescueFailed() public {
        new ForceFeeder{value: 1 ether}(payable(address(engine)));
        EthRejector rejector = new EthRejector();
        vm.expectRevert(IPolicyEngine.RescueFailed.selector);
        engine.sweepStuckETH(payable(address(rejector)));
        assertEq(address(engine).balance, 1 ether); // funds retained
    }

    function test_Lifecycle_RevertsForNonAdmin() public {
        uint256 id = _createBasic();
        vm.prank(stranger);
        vm.expectRevert();
        engine.updatePolicy(id, _params(address(target), operator, PING_SEL));
        vm.prank(stranger);
        vm.expectRevert();
        engine.setPolicyActive(id, false);
        vm.prank(stranger);
        vm.expectRevert();
        engine.deletePolicy(id);
        IPolicyEngine.Policy memory p = engine.getPolicy(id);
        assertTrue(p.active);
        assertEq(p.selector, PAY_SEL);
    }

    function test_GetPolicies_BatchReadAndMissingReverts() public {
        uint256 id1 = _createBasic();
        uint256 id2 = _createBasic();
        uint256[] memory ids = new uint256[](2);
        ids[0] = id1;
        ids[1] = id2;
        IPolicyEngine.Policy[] memory out = engine.getPolicies(ids);
        assertEq(out.length, 2);
        assertEq(out[0].target, address(target));
        assertEq(out[1].target, address(target));

        ids[1] = 999;
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.PolicyNotFound.selector, 999));
        engine.getPolicies(ids);
    }

    function test_CurrentWindowStart_RevertsOnZeroPeriod() public {
        vm.expectRevert(IPolicyEngine.InvalidPolicyConfig.selector);
        engine.currentWindowStart(0);
        vm.warp(1 days + 123);
        assertGt(engine.currentWindowStart(1 days), 0);
    }

    function test_PolicyConfigUpdated_EmittedOnCreateAndUpdate() public {
        uint256 id = engine.nextPolicyId();
        vm.expectEmit(true, false, false, true, address(engine));
        emit IPolicyEngine.PolicyConfigUpdated(
            id, address(target), operator, PAY_SEL, 2 ether, 0, 0, 0, 0, 0, true, 0, 0
        );
        assertEq(engine.createPolicy(_params(address(target), operator, PAY_SEL)), id);

        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, PING_SEL);
        ps.maxValue = 5 ether;
        vm.expectEmit(true, false, false, true, address(engine));
        emit IPolicyEngine.PolicyConfigUpdated(
            id, address(target), operator, PING_SEL, 5 ether, 0, 0, 0, 0, 0, true, 0, 0
        );
        engine.updatePolicy(id, ps);
    }

    function test_DelegationNonceInvalidate_CancelsPendingSignature() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), signer, PAY_SEL);
        uint256 id = engine.createPolicy(ps);
        uint256 deadline = block.timestamp + 1 days;
        bytes memory d = abi.encodeWithSelector(PAY_SEL);
        bytes memory stale = _sign(id, address(target), d, 0, 0, deadline);

        // signer cancels every pending intent by jumping their own nonce
        vm.prank(signer);
        engine.invalidateDelegationNonce(5);
        assertEq(engine.nonces(signer), 5);

        vm.prank(relayer);
        vm.expectRevert(IPolicyEngine.InvalidSignature.selector);
        engine.executeDelegated(id, address(target), d, 0, deadline, stale);

        // fresh intent bound to the new nonce works
        bytes memory fresh = _sign(id, address(target), d, 0, 5, deadline);
        vm.prank(relayer);
        engine.executeDelegated(id, address(target), d, 5, deadline, fresh);
        assertEq(engine.getPolicy(id).execCount, 1);
    }

    function test_InvalidateDelegationNonce_RevertsWhenNotIncreasing() public {
        vm.expectRevert(IPolicyEngine.InvalidNonce.selector);
        engine.invalidateDelegationNonce(0);
        engine.invalidateDelegationNonce(1);
        assertEq(engine.nonces(address(this)), 1);
        vm.expectRevert(IPolicyEngine.InvalidNonce.selector);
        engine.invalidateDelegationNonce(1);
        vm.expectRevert(IPolicyEngine.InvalidNonce.selector);
        engine.invalidateDelegationNonce(0);
    }

    function test_InvalidateDelegationNonce_WorksWhilePaused() public {
        engine.pause();
        vm.prank(signer);
        engine.invalidateDelegationNonce(7);
        assertEq(engine.nonces(signer), 7);
        engine.unpause();
    }

    function test_FailureReturndata_Bounded() public {
        RevertBomb bomb = new RevertBomb();
        IPolicyEngine.PolicyParams memory ps = _params(address(bomb), address(this), bytes4(0));
        uint256 id = engine.createPolicy(ps);

        try this.extExec{value: 0}(id, address(bomb), abi.encodeWithSelector(RevertBomb.fire.selector)) {
            revert("expected TargetCallFailed");
        } catch (bytes memory reason) {
            // TargetCallFailed(policyId, bounded bytes):
            // 4-byte selector + 32-byte id + 32-byte offset + 32-byte length + payload
            uint256 maxLen = 4 + 96 + engine.MAX_FAILURE_RETURNDATA() + 32;
            assertLe(reason.length, maxLen, "returndata not bounded");
            assertGt(reason.length, 4 + 96, "no failure payload bubbled");
        }
        assertEq(engine.getPolicy(id).execCount, 0);
    }

    function test_ExecutionFailedEvent_OnlyInRevertedFrame() public {
        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, SimpleTarget.boom.selector);
        uint256 id = engine.createPolicy(ps);

        vm.recordLogs();
        vm.prank(operator);
        vm.expectRevert();
        engine.execute(id, address(target), abi.encodeWithSelector(SimpleTarget.boom.selector));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 failedTopic = keccak256("PolicyExecutionFailed(uint256,address)");
        bytes32 okTopic = keccak256("PolicyExecuted(uint256,address,address,uint256)");
        bool sawFailed;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics[0] == failedTopic) sawFailed = true;
            assertTrue(logs[i].topics[0] != okTopic, "success event in reverted tx");
        }
        // Documented behavior (AUDIT.md): the failure event exists only in the
        // reverted frame (traces/simulation see it); on-chain it rolls back.
        // Foundry may or may not surface it — either outcome, never a success.
        assertTrue(sawFailed || logs.length == 0, "unexpected log set");
        assertEq(engine.getPolicy(id).execCount, 0);
    }

    function testFuzz_CooldownBoundary(uint64 cdRaw, uint32 warpBy) public {
        uint64 cd = uint64(bound(cdRaw, 1, 30 days));
        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, PAY_SEL);
        ps.cooldown = cd;
        uint256 id = engine.createPolicy(ps);

        vm.prank(operator);
        engine.execute(id, address(target), abi.encodeWithSelector(PAY_SEL));
        uint256 last = engine.getPolicy(id).lastExecution;

        // any warp strictly inside the window must fail closed
        uint256 inside = last + bound(uint256(warpBy), 0, cd == 1 ? 0 : cd - 1);
        vm.warp(inside);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.CooldownActive.selector, last + cd));
        engine.execute(id, address(target), abi.encodeWithSelector(PAY_SEL));

        // exactly at cooldown expiry: allowed
        vm.warp(last + cd);
        vm.prank(operator);
        engine.execute(id, address(target), abi.encodeWithSelector(PAY_SEL));
        assertEq(engine.getPolicy(id).execCount, 2);
    }

    function testFuzz_ArgAmountCapBoundary(uint128 amountRaw, uint128 capRaw) public {
        uint256 cap = bound(capRaw, 1, type(uint96).max);
        uint256 amount = bound(amountRaw, 0, cap + 1000);

        IPolicyEngine.PolicyParams memory ps = _params(address(target), operator, SimpleTarget.transfer.selector);
        ps.maxValue = 0; // zero-value calls only
        ps.argAmountCap = cap;
        ps.argOffset = 36; // uint256 amount word in transfer(address,uint256)
        uint256 id = engine.createPolicy(ps);

        bytes memory d = abi.encodeCall(SimpleTarget.transfer, (operator, amount));
        if (amount <= cap) {
            vm.prank(operator);
            engine.execute(id, address(target), d);
            assertEq(engine.getPolicy(id).execCount, 1);
        } else {
            vm.prank(operator);
            vm.expectRevert(abi.encodeWithSelector(IPolicyEngine.ArgAmountExceeded.selector, amount, cap));
            engine.execute(id, address(target), d);
            assertEq(engine.getPolicy(id).execCount, 0);
        }
    }
}
