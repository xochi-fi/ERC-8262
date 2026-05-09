// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {XochiTimelock} from "../src/XochiTimelock.sol";
import {XochiZKPVerifier} from "../src/XochiZKPVerifier.sol";
import {XochiZKPOracle} from "../src/XochiZKPOracle.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";

/// @dev Stub verifier for timelock integration tests
contract StubVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract XochiTimelockTest is Test {
    XochiTimelock internal timelock;
    XochiZKPVerifier internal verifier;
    XochiZKPOracle internal oracle;

    address internal multisig = makeAddr("multisig");
    address internal guardian = makeAddr("guardian");
    address internal deployer = makeAddr("deployer");
    address internal alice = makeAddr("alice");

    bytes32 internal constant CONFIG_HASH = bytes32(uint256(0xc0ffee));

    function _defaultProviders() internal pure returns (uint256[] memory ps) {
        ps = new uint256[](1);
        ps[0] = 1;
    }

    function setUp() public {
        timelock = new XochiTimelock(multisig, guardian);

        // Deploy contracts owned by deployer, then transfer to timelock
        vm.startPrank(deployer);
        verifier = new XochiZKPVerifier(deployer);
        oracle = new XochiZKPOracle(address(verifier), deployer, CONFIG_HASH, _defaultProviders());

        // Register a stub verifier for compliance (needed for some integration tests)
        StubVerifier stub = new StubVerifier();
        verifier.setVerifierInitial(ProofTypes.COMPLIANCE, address(stub));

        // Transfer ownership to timelock
        verifier.transferOwnership(address(timelock));
        oracle.transferOwnership(address(timelock));
        vm.stopPrank();

        // Timelock accepts ownership via the standard schedule + execute path
        // (audit F-5: the convenience `acceptOwnership(address)` shortcut was
        // removed; every action goes through the configured delay).
        bytes memory acceptCall = abi.encodeWithSignature("acceptOwnership()");
        bytes32 saltV = bytes32(uint256(0xACCE7));
        bytes32 saltO = bytes32(uint256(0xACCE8));

        vm.startPrank(multisig);
        timelock.schedule(address(verifier), 0, acceptCall, saltV);
        timelock.schedule(address(oracle), 0, acceptCall, saltO);
        vm.stopPrank();

        vm.warp(block.timestamp + timelock.HIGH_DELAY());

        timelock.execute(address(verifier), 0, acceptCall, saltV);
        timelock.execute(address(oracle), 0, acceptCall, saltO);
    }

    // -------------------------------------------------------------------------
    // Ownership transfer
    // -------------------------------------------------------------------------

    function test_timelockOwnsVerifier() public view {
        assertEq(verifier.owner(), address(timelock));
    }

    function test_timelockOwnsOracle() public view {
        assertEq(oracle.owner(), address(timelock));
    }

    // -------------------------------------------------------------------------
    // Schedule + execute happy path
    // -------------------------------------------------------------------------

    function test_schedule_execute_lowDelay() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(1));

        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);

        bytes32 id = timelock.hashOperation(address(oracle), 0, data, salt);
        assertGt(timelock.getOperationState(id), 1);

        // Too early
        vm.warp(block.timestamp + 6 hours - 1);
        vm.expectRevert(abi.encodeWithSelector(XochiTimelock.OperationNotReady.selector, id, block.timestamp + 1));
        timelock.execute(address(oracle), 0, data, salt);

        // Exact boundary
        vm.warp(block.timestamp + 1);
        timelock.execute(address(oracle), 0, data, salt);

        // Verify TTL changed
        assertEq(oracle.attestationTTL(), 48 hours);
        assertEq(timelock.getOperationState(id), 1);
    }

    function test_schedule_execute_highDelay() public {
        // Propose a new verifier (high delay)
        StubVerifier newStub = new StubVerifier();
        bytes memory data =
            abi.encodeWithSignature("proposeVerifier(uint8,address)", ProofTypes.RISK_SCORE, address(newStub));
        bytes32 salt = bytes32(uint256(2));

        vm.prank(multisig);
        timelock.schedule(address(verifier), 0, data, salt);

        // 6h is not enough
        vm.warp(block.timestamp + 6 hours);
        bytes32 id = timelock.hashOperation(address(verifier), 0, data, salt);
        vm.expectRevert();
        timelock.execute(address(verifier), 0, data, salt);

        // 24h works
        vm.warp(block.timestamp + 18 hours);
        timelock.execute(address(verifier), 0, data, salt);

        (address proposed,) = verifier.getPendingVerifier(ProofTypes.RISK_SCORE);
        assertEq(proposed, address(newStub));
    }

    // -------------------------------------------------------------------------
    // Delay classification
    // -------------------------------------------------------------------------

    function test_delay_lowDelay_configOps() public view {
        assertEq(timelock.getDelay(bytes4(keccak256("updateProviderConfig(bytes32,string,uint256[])"))), 6 hours);
        assertEq(timelock.getDelay(bytes4(keccak256("updateAttestationTTL(uint256)"))), 6 hours);
        assertEq(timelock.getDelay(bytes4(keccak256("registerMerkleRoot(bytes32)"))), 6 hours);
        assertEq(timelock.getDelay(bytes4(keccak256("revokeMerkleRoot(bytes32)"))), 6 hours);
        assertEq(timelock.getDelay(bytes4(keccak256("registerReportingThreshold(bytes32)"))), 6 hours);
        assertEq(timelock.getDelay(bytes4(keccak256("revokeReportingThreshold(bytes32)"))), 6 hours);
        assertEq(timelock.getDelay(bytes4(keccak256("revokeConfig(bytes32)"))), 6 hours);
        // Audit I-3: revokeVerifierVersion is housekeeping (pauseProofType is the
        // emergency lever); LOW_DELAY protects against compromised-owner DoS.
        assertEq(timelock.getDelay(bytes4(keccak256("revokeVerifierVersion(uint8,uint256)"))), 6 hours);
    }

    function test_delay_highDelay_verifierOps() public view {
        assertEq(timelock.getDelay(bytes4(keccak256("proposeVerifier(uint8,address)"))), 24 hours);
        assertEq(timelock.getDelay(bytes4(keccak256("setVerifierInitial(uint8,address)"))), 24 hours);
        assertEq(timelock.getDelay(bytes4(keccak256("transferOwnership(address)"))), 24 hours);
    }

    function test_delay_unknownSelector_defaultsHigh() public view {
        assertEq(timelock.getDelay(bytes4(keccak256("unknownFunction()"))), 24 hours);
    }

    // -------------------------------------------------------------------------
    // Access control
    // -------------------------------------------------------------------------

    function test_schedule_revert_notProposer() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        vm.prank(alice);
        vm.expectRevert(XochiTimelock.NotProposer.selector);
        timelock.schedule(address(oracle), 0, data, bytes32(0));
    }

    function test_cancel_byProposer() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(3));

        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);

        bytes32 id = timelock.hashOperation(address(oracle), 0, data, salt);

        vm.prank(multisig);
        timelock.cancel(id);

        assertEq(timelock.getOperationState(id), 0);
    }

    function test_cancel_byGuardian() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(4));

        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);

        bytes32 id = timelock.hashOperation(address(oracle), 0, data, salt);

        vm.prank(guardian);
        timelock.cancel(id);

        assertEq(timelock.getOperationState(id), 0);
    }

    function test_cancel_revert_notAuthorized() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(5));

        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);

        bytes32 id = timelock.hashOperation(address(oracle), 0, data, salt);

        vm.prank(alice);
        vm.expectRevert(XochiTimelock.NotAuthorized.selector);
        timelock.cancel(id);
    }

    // -------------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------------

    function test_schedule_revert_duplicate() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(6));

        vm.startPrank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);

        bytes32 id = timelock.hashOperation(address(oracle), 0, data, salt);
        vm.expectRevert(abi.encodeWithSelector(XochiTimelock.OperationAlreadyScheduled.selector, id));
        timelock.schedule(address(oracle), 0, data, salt);
        vm.stopPrank();
    }

    function test_execute_revert_notScheduled() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 id = timelock.hashOperation(address(oracle), 0, data, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(XochiTimelock.OperationNotScheduled.selector, id));
        timelock.execute(address(oracle), 0, data, bytes32(0));
    }

    function test_execute_revert_alreadyExecuted() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(7));

        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);

        vm.warp(block.timestamp + 6 hours);
        timelock.execute(address(oracle), 0, data, salt);

        bytes32 id = timelock.hashOperation(address(oracle), 0, data, salt);
        vm.expectRevert(abi.encodeWithSelector(XochiTimelock.OperationAlreadyExecuted.selector, id));
        timelock.execute(address(oracle), 0, data, salt);
    }

    function test_reschedule_afterCancel() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(8));

        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);

        bytes32 id = timelock.hashOperation(address(oracle), 0, data, salt);
        vm.prank(multisig);
        timelock.cancel(id);

        // Should be reschedulable
        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);
        assertGt(timelock.getOperationState(id), 1);
    }

    function test_isOperationReady() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(9));

        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);

        bytes32 id = timelock.hashOperation(address(oracle), 0, data, salt);
        assertFalse(timelock.isOperationReady(id));

        vm.warp(block.timestamp + 6 hours);
        assertTrue(timelock.isOperationReady(id));
    }

    // -------------------------------------------------------------------------
    // Self-administration
    // -------------------------------------------------------------------------

    function test_updateProposer_viaSelf() public {
        address newMultisig = makeAddr("newMultisig");
        bytes memory data = abi.encodeWithSignature("updateProposer(address)", newMultisig);
        bytes32 salt = bytes32(uint256(10));

        vm.prank(multisig);
        timelock.schedule(address(timelock), 0, data, salt);

        vm.warp(block.timestamp + 24 hours);
        timelock.execute(address(timelock), 0, data, salt);

        assertEq(timelock.proposer(), newMultisig);
    }

    function test_updateProposer_revert_directCall() public {
        vm.prank(multisig);
        vm.expectRevert(XochiTimelock.NotProposer.selector);
        timelock.updateProposer(alice);
    }

    // -------------------------------------------------------------------------
    // End-to-end: config update through timelock
    // -------------------------------------------------------------------------

    function test_e2e_registerMerkleRoot() public {
        bytes32 root = bytes32(uint256(0xdeadbeef));
        bytes memory data = abi.encodeWithSignature("registerMerkleRoot(bytes32)", root);
        bytes32 salt = bytes32(uint256(11));

        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);

        vm.warp(block.timestamp + 6 hours);
        timelock.execute(address(oracle), 0, data, salt);

        assertTrue(oracle.isValidMerkleRoot(root));
    }

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    function test_schedule_emitsEvent() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(12));
        bytes32 id = timelock.hashOperation(address(oracle), 0, data, salt);
        uint256 readyAt = block.timestamp + 6 hours;

        vm.prank(multisig);
        vm.expectEmit(true, true, false, true);
        emit XochiTimelock.OperationScheduled(id, address(oracle), 0, data, readyAt);
        timelock.schedule(address(oracle), 0, data, salt);
    }

    function test_execute_emitsEvent() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(13));
        bytes32 id = timelock.hashOperation(address(oracle), 0, data, salt);

        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);

        vm.warp(block.timestamp + 6 hours);
        vm.expectEmit(true, true, false, true);
        emit XochiTimelock.OperationExecuted(id, address(oracle), 0, data);
        timelock.execute(address(oracle), 0, data, salt);
    }

    function test_cancel_emitsEvent() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(14));
        bytes32 id = timelock.hashOperation(address(oracle), 0, data, salt);

        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);

        vm.prank(multisig);
        vm.expectEmit(true, false, false, false);
        emit XochiTimelock.OperationCancelled(id);
        timelock.cancel(id);
    }

    // -------------------------------------------------------------------------
    // L-1: msg.value vs scheduled value
    // -------------------------------------------------------------------------

    function test_execute_revert_valueMismatch() public {
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(99));

        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);
        vm.warp(block.timestamp + 6 hours);

        // Send msg.value=1 wei against a scheduled value=0 -> reject (locks funds otherwise)
        vm.deal(address(this), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(XochiTimelock.ValueMismatch.selector, 1, 0));
        timelock.execute{value: 1}(address(oracle), 0, data, salt);
    }

    function test_execute_acceptsExactValue() public {
        // Schedule a self-call with value=0; msg.value=0 must still work
        bytes memory data = abi.encodeWithSignature("updateAttestationTTL(uint256)", 48 hours);
        bytes32 salt = bytes32(uint256(100));

        vm.prank(multisig);
        timelock.schedule(address(oracle), 0, data, salt);
        vm.warp(block.timestamp + 6 hours);
        timelock.execute{value: 0}(address(oracle), 0, data, salt);
    }
}
