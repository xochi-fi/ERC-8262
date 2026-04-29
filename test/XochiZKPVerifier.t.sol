// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {XochiZKPVerifier} from "../src/XochiZKPVerifier.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";
import {Ownable2Step} from "../src/libraries/Ownable2Step.sol";
import {AccessControl} from "../src/libraries/AccessControl.sol";
import {Pausable} from "../src/libraries/Pausable.sol";

/// @dev Stub verifier that always returns true (for unit testing the router logic)
contract StubVerifier is IUltraVerifier {
    bool public shouldPass;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return shouldPass;
    }
}

/// @dev Regression: malicious verifier that attempts to mutate state from inside verify().
///      The IUltraVerifier interface declares verify() as `view`, so Solidity emits a
///      STATICCALL at the CALLER (XochiZKPVerifier) when invoking it. STATICCALL halts
///      on any SSTORE, LOG, CREATE, SELFDESTRUCT, or CALL with non-zero value -- the
///      EVM-level guarantee that protects the router from a malicious verifier.
///
///      Note: this contract intentionally does NOT inherit IUltraVerifier. Its verify()
///      function is declared non-view (writes to `counter`) so the compiler is happy.
///      The selector matches IUltraVerifier.verify, so the router can cast and call it.
///      At runtime the call is STATICCALL (per the interface used at the call site),
///      so the SSTORE fails and the entire call reverts.
contract MutatingVerifier {
    uint256 public counter;

    function verify(bytes calldata, bytes32[] calldata) external returns (bool) {
        counter += 1; // SSTORE under STATICCALL must revert
        return true;
    }
}

contract XochiZKPVerifierTest is Test {
    XochiZKPVerifier internal verifier;
    StubVerifier internal passingVerifier;
    StubVerifier internal failingVerifier;

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");

    function setUp() public {
        verifier = new XochiZKPVerifier(owner);
        passingVerifier = new StubVerifier(true);
        failingVerifier = new StubVerifier(false);

        vm.startPrank(owner);
        verifier.setVerifierInitial(ProofTypes.COMPLIANCE, address(passingVerifier));
        verifier.setVerifierInitial(ProofTypes.RISK_SCORE, address(passingVerifier));
        verifier.setVerifierInitial(ProofTypes.PATTERN, address(passingVerifier));
        verifier.setVerifierInitial(ProofTypes.ATTESTATION, address(passingVerifier));
        verifier.setVerifierInitial(ProofTypes.MEMBERSHIP, address(passingVerifier));
        verifier.setVerifierInitial(ProofTypes.NON_MEMBERSHIP, address(passingVerifier));
        vm.stopPrank();
    }

    /// @dev Deploy a fresh StubVerifier (passes code existence check)
    function _newStub() internal returns (address) {
        return address(new StubVerifier(true));
    }

    /// @dev Upgrade a verifier via the timelock: propose, warp, execute
    function _upgradeVerifier(uint8 proofType, address newVerifier) internal {
        vm.prank(owner);
        verifier.proposeVerifier(proofType, newVerifier);
        vm.warp(block.timestamp + 24 hours);
        vm.prank(owner);
        verifier.executeVerifierUpdate(proofType);
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    function test_constructor_setsOwner() public view {
        assertEq(verifier.owner(), owner);
    }

    function test_constructor_revert_zeroAddress() public {
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        new XochiZKPVerifier(address(0));
    }

    // -------------------------------------------------------------------------
    // verifyProof
    // -------------------------------------------------------------------------

    function test_verifyProof_compliance_valid() public {
        assertTrue(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));
    }

    function test_verifyProof_riskScore_valid() public {
        assertTrue(verifier.verifyProof(ProofTypes.RISK_SCORE, _dummyProof(), _riskScoreInputs()));
    }

    function test_verifyProof_pattern_valid() public {
        assertTrue(verifier.verifyProof(ProofTypes.PATTERN, _dummyProof(), _patternInputs()));
    }

    function test_verifyProof_attestation_valid() public {
        assertTrue(verifier.verifyProof(ProofTypes.ATTESTATION, _dummyProof(), _attestationInputs()));
    }

    function test_verifyProof_membership_valid() public {
        assertTrue(verifier.verifyProof(ProofTypes.MEMBERSHIP, _dummyProof(), _membershipInputs()));
    }

    function test_verifyProof_nonMembership_valid() public {
        assertTrue(verifier.verifyProof(ProofTypes.NON_MEMBERSHIP, _dummyProof(), _nonMembershipInputs()));
    }

    function test_verifyProof_revert_invalidProofType() public {
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x00));
        verifier.verifyProof(0x00, _dummyProof(), _complianceInputs());

        // 0x07 (COMPLIANCE_SIGNED) and 0x08 (RISK_SCORE_SIGNED) are valid;
        // 0x09 is the next out-of-range type.
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x09));
        verifier.verifyProof(0x09, _dummyProof(), _complianceInputs());
    }

    function test_verifyProof_revert_verifierNotSet() public {
        XochiZKPVerifier fresh = new XochiZKPVerifier(owner);

        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.VerifierNotSet.selector, ProofTypes.COMPLIANCE));
        fresh.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs());
    }

    function test_verifyProof_revert_wrongPublicInputCount() public {
        // Compliance expects 6 inputs, give it 3
        bytes memory badInputs = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)));

        vm.expectRevert(
            abi.encodeWithSelector(ProofTypes.InvalidPublicInputLength.selector, ProofTypes.COMPLIANCE, 6, 3)
        );
        verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), badInputs);
    }

    function test_verifyProof_failingVerifier() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        assertFalse(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));
    }

    // -------------------------------------------------------------------------
    // verifyProofBatch
    // -------------------------------------------------------------------------

    function test_verifyProofBatch_allValid() public {
        uint8[] memory types = new uint8[](2);
        types[0] = ProofTypes.COMPLIANCE;
        types[1] = ProofTypes.RISK_SCORE;

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = _dummyProof();
        proofs[1] = _dummyProof();

        bytes[] memory inputs = new bytes[](2);
        inputs[0] = _complianceInputs();
        inputs[1] = _riskScoreInputs();

        assertTrue(verifier.verifyProofBatch(types, proofs, inputs));
    }

    function test_verifyProofBatch_oneFails() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        uint8[] memory types = new uint8[](2);
        types[0] = ProofTypes.COMPLIANCE;
        types[1] = ProofTypes.RISK_SCORE;

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = _dummyProof();
        proofs[1] = _dummyProof();

        bytes[] memory inputs = new bytes[](2);
        inputs[0] = _complianceInputs();
        inputs[1] = _riskScoreInputs();

        assertFalse(verifier.verifyProofBatch(types, proofs, inputs));
    }

    function test_verifyProofBatch_revert_emptyBatch() public {
        vm.expectRevert(XochiZKPVerifier.EmptyBatch.selector);
        verifier.verifyProofBatch(new uint8[](0), new bytes[](0), new bytes[](0));
    }

    function test_verifyProofBatch_revert_batchTooLarge() public {
        uint256 size = verifier.MAX_BATCH_SIZE() + 1;
        uint8[] memory types = new uint8[](size);
        bytes[] memory proofs = new bytes[](size);
        bytes[] memory inputs = new bytes[](size);

        vm.expectRevert(XochiZKPVerifier.BatchTooLarge.selector);
        verifier.verifyProofBatch(types, proofs, inputs);
    }

    function test_verifyProofBatch_revert_lengthMismatch() public {
        uint8[] memory types = new uint8[](2);
        bytes[] memory proofs = new bytes[](1);
        bytes[] memory inputs = new bytes[](2);

        vm.expectRevert(XochiZKPVerifier.BatchLengthMismatch.selector);
        verifier.verifyProofBatch(types, proofs, inputs);
    }

    // -------------------------------------------------------------------------
    // Admin: setVerifierInitial
    // -------------------------------------------------------------------------

    function test_setVerifierInitial_revert_alreadySet() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.VerifierAlreadySet.selector, ProofTypes.COMPLIANCE));
        verifier.setVerifierInitial(ProofTypes.COMPLIANCE, address(passingVerifier));
    }

    function test_setVerifierInitial_fresh() public {
        XochiZKPVerifier fresh = new XochiZKPVerifier(owner);
        address newVerifier = _newStub();
        vm.prank(owner);
        fresh.setVerifierInitial(ProofTypes.COMPLIANCE, newVerifier);
        assertEq(fresh.getVerifier(ProofTypes.COMPLIANCE), newVerifier);
    }

    function test_setVerifierInitial_revert_notOwner() public {
        XochiZKPVerifier fresh = new XochiZKPVerifier(owner);
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        fresh.setVerifierInitial(ProofTypes.COMPLIANCE, address(passingVerifier));
    }

    function test_setVerifierInitial_revert_zeroAddress() public {
        XochiZKPVerifier fresh = new XochiZKPVerifier(owner);
        vm.prank(owner);
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        fresh.setVerifierInitial(ProofTypes.COMPLIANCE, address(0));
    }

    function test_setVerifierInitial_revert_invalidProofType() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x09));
        verifier.setVerifierInitial(0x09, address(passingVerifier));
    }

    function test_setVerifierInitial_revert_notAContract() public {
        XochiZKPVerifier fresh = new XochiZKPVerifier(owner);
        address eoa = makeAddr("eoa");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.NotAContract.selector, eoa));
        fresh.setVerifierInitial(ProofTypes.COMPLIANCE, eoa);
    }

    function test_proposeVerifier_revert_notAContract() public {
        address eoa = makeAddr("eoa");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.NotAContract.selector, eoa));
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, eoa);
    }

    // -------------------------------------------------------------------------
    // Admin: proposeVerifier / executeVerifierUpdate / cancelVerifierProposal
    // -------------------------------------------------------------------------

    function test_proposeVerifier_setsProposal() public {
        address newVerifier = _newStub();
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier);

        (address proposed, uint256 readyAt) = verifier.getPendingVerifier(ProofTypes.COMPLIANCE);
        assertEq(proposed, newVerifier);
        assertEq(readyAt, block.timestamp + 24 hours);
    }

    function test_executeVerifierUpdate_afterTimelock() public {
        address newVerifier = _newStub();
        _upgradeVerifier(ProofTypes.COMPLIANCE, newVerifier);
        assertEq(verifier.getVerifier(ProofTypes.COMPLIANCE), newVerifier);
    }

    function test_executeVerifierUpdate_revert_beforeTimelock() public {
        address newVerifier = _newStub();
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier);

        vm.warp(block.timestamp + 24 hours - 1);
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                XochiZKPVerifier.TimelockNotElapsed.selector, ProofTypes.COMPLIANCE, block.timestamp + 1
            )
        );
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
    }

    function test_executeVerifierUpdate_exactBoundary() public {
        address newVerifier = _newStub();
        uint256 proposeTime = block.timestamp;
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier);

        vm.warp(proposeTime + 24 hours);
        vm.prank(owner);
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
        assertEq(verifier.getVerifier(ProofTypes.COMPLIANCE), newVerifier);
    }

    function test_cancelVerifierProposal() public {
        address newVerifier = _newStub();
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier);

        vm.prank(owner);
        verifier.cancelVerifierProposal(ProofTypes.COMPLIANCE);

        (address proposed, uint256 readyAt) = verifier.getPendingVerifier(ProofTypes.COMPLIANCE);
        assertEq(proposed, address(0));
        assertEq(readyAt, 0);
    }

    function test_cancelVerifierProposal_revert_noPending() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.NoPendingProposal.selector, ProofTypes.COMPLIANCE));
        verifier.cancelVerifierProposal(ProofTypes.COMPLIANCE);
    }

    function test_proposeVerifier_revert_alreadyPending() public {
        address v1 = _newStub();
        address v2 = _newStub();
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, v1);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.ProposalAlreadyPending.selector, ProofTypes.COMPLIANCE));
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, v2);
    }

    function test_executeVerifierUpdate_revert_noPending() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.NoPendingProposal.selector, ProofTypes.COMPLIANCE));
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
    }

    function test_executeVerifierUpdate_emitsEvent() public {
        address newVerifier = _newStub();
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier);

        vm.warp(block.timestamp + 24 hours);
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit XochiZKPVerifier.VerifierUpdated(ProofTypes.COMPLIANCE, address(passingVerifier), newVerifier);
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
    }

    function test_proposeVerifier_emitsEvent() public {
        address newVerifier = _newStub();
        uint256 readyAt = block.timestamp + 24 hours;
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit XochiZKPVerifier.VerifierProposed(ProofTypes.COMPLIANCE, newVerifier, readyAt);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier);
    }

    function test_getPendingVerifier_noPending() public view {
        (address proposed, uint256 readyAt) = verifier.getPendingVerifier(ProofTypes.COMPLIANCE);
        assertEq(proposed, address(0));
        assertEq(readyAt, 0);
    }

    // -------------------------------------------------------------------------
    // Ownership
    // -------------------------------------------------------------------------

    function test_transferOwnership_twoStep() public {
        vm.prank(owner);
        verifier.transferOwnership(alice);
        assertEq(verifier.pendingOwner(), alice);
        assertEq(verifier.owner(), owner);

        vm.prank(alice);
        verifier.acceptOwnership();
        assertEq(verifier.owner(), alice);
        assertEq(verifier.pendingOwner(), address(0));
    }

    function test_transferOwnership_revert_notOwner() public {
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        verifier.transferOwnership(alice);
    }

    function test_acceptOwnership_revert_notPending() public {
        vm.prank(owner);
        verifier.transferOwnership(alice);

        vm.prank(makeAddr("bob"));
        vm.expectRevert(Ownable2Step.NotPendingOwner.selector);
        verifier.acceptOwnership();
    }

    function test_acceptOwnership_revert_expired() public {
        vm.prank(owner);
        verifier.transferOwnership(alice);

        vm.warp(block.timestamp + 48 hours + 1);

        vm.prank(alice);
        vm.expectRevert(Ownable2Step.OwnershipTransferExpired.selector);
        verifier.acceptOwnership();
    }

    // -------------------------------------------------------------------------
    // Verifier upgrade scenarios
    // -------------------------------------------------------------------------

    function test_verifierUpgrade_newVerifierUsed() public {
        // Start with passing verifier, upgrade to failing
        assertTrue(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));

        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        assertFalse(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));
    }

    function test_verifierUpgrade_otherTypesUnaffected() public {
        // Upgrade only COMPLIANCE, others should still pass
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        assertFalse(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));
        assertTrue(verifier.verifyProof(ProofTypes.RISK_SCORE, _dummyProof(), _riskScoreInputs()));
        assertTrue(verifier.verifyProof(ProofTypes.MEMBERSHIP, _dummyProof(), _membershipInputs()));
    }

    // -------------------------------------------------------------------------
    // Verifier history
    // -------------------------------------------------------------------------

    function test_verifierUpgrade_buildsHistory() public {
        // setUp already called setVerifierInitial for each type (version 1)
        assertEq(verifier.getVerifierVersion(ProofTypes.COMPLIANCE), 1);
        assertEq(verifier.getVerifierAtVersion(ProofTypes.COMPLIANCE, 1), address(passingVerifier));

        // Upgrade to version 2 via timelock
        address v2 = _newStub();
        _upgradeVerifier(ProofTypes.COMPLIANCE, v2);

        assertEq(verifier.getVerifierVersion(ProofTypes.COMPLIANCE), 2);
        assertEq(verifier.getVerifierAtVersion(ProofTypes.COMPLIANCE, 1), address(passingVerifier));
        assertEq(verifier.getVerifierAtVersion(ProofTypes.COMPLIANCE, 2), v2);
    }

    function test_verifyProofAtVersion_routesToHistorical() public {
        // Upgrade COMPLIANCE to failing verifier (version 2) via timelock
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        // Version 1 (passing) should still return true
        assertTrue(verifier.verifyProofAtVersion(ProofTypes.COMPLIANCE, 1, _dummyProof(), _complianceInputs()));
        // Version 2 (failing) should return false
        assertFalse(verifier.verifyProofAtVersion(ProofTypes.COMPLIANCE, 2, _dummyProof(), _complianceInputs()));
    }

    function test_getVerifierAtVersion_revert_invalidVersion() public {
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 0));
        verifier.getVerifierAtVersion(ProofTypes.COMPLIANCE, 0);

        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 99));
        verifier.getVerifierAtVersion(ProofTypes.COMPLIANCE, 99);
    }

    function test_getVerifierVersion_noVerifierSet() public {
        XochiZKPVerifier fresh = new XochiZKPVerifier(owner);
        assertEq(fresh.getVerifierVersion(ProofTypes.COMPLIANCE), 0);
    }

    // -------------------------------------------------------------------------
    // Verifier version revocation
    // -------------------------------------------------------------------------

    function test_revokeVerifierVersion() public {
        // Upgrade to v2 so v1 can be revoked
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        // v1 works before revocation
        assertTrue(verifier.verifyProofAtVersion(ProofTypes.COMPLIANCE, 1, _dummyProof(), _complianceInputs()));

        // Revoke v1
        vm.prank(owner);
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);
        assertTrue(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 1));

        // v1 is now blocked
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.VersionRevoked.selector, ProofTypes.COMPLIANCE, 1));
        verifier.verifyProofAtVersion(ProofTypes.COMPLIANCE, 1, _dummyProof(), _complianceInputs());
    }

    function test_revokeVerifierVersion_emitsEvent() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit XochiZKPVerifier.VerifierVersionRevoked(ProofTypes.COMPLIANCE, 1, address(passingVerifier));
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);
    }

    function test_revokeVerifierVersion_revert_currentVersion() public {
        // Only v1 exists, can't revoke current
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPVerifier.CannotRevokeCurrentVersion.selector, ProofTypes.COMPLIANCE)
        );
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);
    }

    function test_revokeVerifierVersion_revert_alreadyRevoked() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        vm.prank(owner);
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.AlreadyRevoked.selector, ProofTypes.COMPLIANCE, 1));
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);
    }

    function test_revokeVerifierVersion_revert_invalidVersion() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 0));
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 0);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 99));
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 99);
    }

    function test_revokeVerifierVersion_revert_notOwner() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);
    }

    function test_isVersionRevoked_falseByDefault() public view {
        assertFalse(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 1));
    }

    // -------------------------------------------------------------------------
    // I-3: Timelocked propose/execute revocation
    // -------------------------------------------------------------------------

    function test_proposeVersionRevocation_succeeds() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        uint256 readyAt = block.timestamp + verifier.REVOCATION_TIMELOCK();

        vm.expectEmit(true, true, false, true);
        emit XochiZKPVerifier.VersionRevocationProposed(ProofTypes.COMPLIANCE, 1, readyAt);
        vm.prank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        assertEq(verifier.getPendingRevocation(ProofTypes.COMPLIANCE, 1), readyAt);
        // Version is NOT yet revoked
        assertFalse(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 1));
    }

    function test_proposeVersionRevocation_revert_currentVersion() public {
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPVerifier.CannotRevokeCurrentVersion.selector, ProofTypes.COMPLIANCE)
        );
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
    }

    function test_proposeVersionRevocation_revert_alreadyRevoked() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));
        vm.prank(owner);
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.AlreadyRevoked.selector, ProofTypes.COMPLIANCE, 1));
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
    }

    function test_proposeVersionRevocation_revert_alreadyPending() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        vm.startPrank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.ProposalAlreadyPending.selector, ProofTypes.COMPLIANCE));
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
        vm.stopPrank();
    }

    function test_proposeVersionRevocation_revert_invalidVersion() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 0));
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 0);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 99));
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 99);
    }

    function test_proposeVersionRevocation_revert_notOwner() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
    }

    function test_executeVersionRevocation_succeeds() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        vm.prank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        // Cannot execute before delay elapses
        uint256 readyAt = block.timestamp + verifier.REVOCATION_TIMELOCK();
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPVerifier.TimelockNotElapsed.selector, ProofTypes.COMPLIANCE, readyAt)
        );
        vm.prank(owner);
        verifier.executeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        // Just before ready
        vm.warp(readyAt - 1);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPVerifier.TimelockNotElapsed.selector, ProofTypes.COMPLIANCE, readyAt)
        );
        vm.prank(owner);
        verifier.executeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        // At ready time -- success
        vm.warp(readyAt);
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit XochiZKPVerifier.VerifierVersionRevoked(ProofTypes.COMPLIANCE, 1, address(passingVerifier));
        verifier.executeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        assertTrue(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 1));
        // Pending state cleared
        assertEq(verifier.getPendingRevocation(ProofTypes.COMPLIANCE, 1), 0);
    }

    function test_executeVersionRevocation_revert_noPendingProposal() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.NoPendingProposal.selector, ProofTypes.COMPLIANCE));
        verifier.executeVersionRevocation(ProofTypes.COMPLIANCE, 1);
    }

    function test_cancelVersionRevocation_succeeds() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        vm.prank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit XochiZKPVerifier.VersionRevocationCancelled(ProofTypes.COMPLIANCE, 1);
        verifier.cancelVersionRevocation(ProofTypes.COMPLIANCE, 1);

        assertEq(verifier.getPendingRevocation(ProofTypes.COMPLIANCE, 1), 0);
        assertFalse(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 1));

        // After cancellation, can re-propose
        vm.prank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
    }

    function test_cancelVersionRevocation_revert_noPendingProposal() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.NoPendingProposal.selector, ProofTypes.COMPLIANCE));
        verifier.cancelVersionRevocation(ProofTypes.COMPLIANCE, 1);
    }

    function test_cancelVersionRevocation_revert_notOwner() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));
        vm.prank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        verifier.cancelVersionRevocation(ProofTypes.COMPLIANCE, 1);
    }

    function test_executeVersionRevocation_independentVersions() public {
        // Build a 3-version history (v1, v2, v3 current)
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));
        StubVerifier v3 = new StubVerifier(true);
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(v3));

        // Propose revocation of v1 and v2 independently
        vm.startPrank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 2);
        vm.stopPrank();

        vm.warp(block.timestamp + verifier.REVOCATION_TIMELOCK());

        vm.startPrank(owner);
        verifier.executeVersionRevocation(ProofTypes.COMPLIANCE, 1);
        verifier.executeVersionRevocation(ProofTypes.COMPLIANCE, 2);
        vm.stopPrank();

        assertTrue(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 1));
        assertTrue(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 2));
        // Current version (v3) is NOT revoked
        assertFalse(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 3));
    }

    // -------------------------------------------------------------------------
    // Regression: STATICCALL protection against state-mutating verifier
    // -------------------------------------------------------------------------

    function test_staticcall_prevents_mutatingVerifier() public {
        // Deploy a malicious verifier that attempts SSTORE inside verify()
        MutatingVerifier malicious = new MutatingVerifier();

        // Replace COMPLIANCE verifier with the malicious one (via timelock dance)
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(malicious));

        // Call verifyProof: routed through STATICCALL, malicious SSTORE must revert.
        // The bb-generated verifier interface returns (bool); revert here means the
        // EVM rejected the inner mutation. Either revert or false is acceptable in
        // theory, but the SSTORE attempt MUST trigger a revert under STATICCALL.
        vm.expectRevert();
        verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs());
    }

    function test_executeVersionRevocation_revert_versionBecameCurrent() public {
        // Edge case: version exists, new versions get added, but never becomes "current"
        // because current = history.length. Versions only ever stay non-current.
        // This test verifies the semantics: once a version is < history.length, it stays so.
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        vm.prank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        // Add another version while proposal is pending
        StubVerifier v3 = new StubVerifier(true);
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(v3));

        vm.warp(block.timestamp + verifier.REVOCATION_TIMELOCK());
        vm.prank(owner);
        verifier.executeVersionRevocation(ProofTypes.COMPLIANCE, 1);
        assertTrue(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 1));
    }

    // -------------------------------------------------------------------------
    // Fuzz: proof type validation
    // -------------------------------------------------------------------------

    function testFuzz_verifyProof_revert_invalidProofType(uint8 proofType) public {
        // 0x07 (COMPLIANCE_SIGNED) and 0x08 (RISK_SCORE_SIGNED) are valid; 0x09+ are not.
        vm.assume(proofType == 0 || proofType > 8);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, proofType));
        verifier.verifyProof(proofType, _dummyProof(), _complianceInputs());
    }

    function testFuzz_proposeVerifier_revert_invalidProofType(uint8 proofType) public {
        vm.assume(proofType == 0 || proofType > 8);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, proofType));
        verifier.proposeVerifier(proofType, address(passingVerifier));
    }

    // -------------------------------------------------------------------------
    // View correctness (Finding 3)
    // -------------------------------------------------------------------------

    function test_verifyProof_isView() public view {
        // After the view fix, verifyProof should be callable in a view context.
        // This test compiles only if the function signature is view.
        verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs());
    }

    // -------------------------------------------------------------------------
    // Unaligned public inputs (Finding 1)
    // -------------------------------------------------------------------------

    function test_verifyProof_revert_unalignedPublicInputs() public {
        bytes memory unaligned = new bytes(193); // 6*32 + 1
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.UnalignedPublicInputs.selector, 193));
        verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), unaligned);
    }

    function testFuzz_verifyProof_revert_unalignedPublicInputs(uint256 extra) public {
        extra = bound(extra, 1, 31);
        bytes memory unaligned = new bytes(6 * 32 + extra);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.UnalignedPublicInputs.selector, 6 * 32 + extra));
        verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), unaligned);
    }

    // -------------------------------------------------------------------------
    // Pause mechanism
    // -------------------------------------------------------------------------

    function test_pause_blocksVerifyProof() public {
        vm.prank(owner);
        verifier.pause();

        vm.expectRevert(Pausable.ContractPaused.selector);
        verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs());
    }

    function test_pause_blocksVerifyProofBatch() public {
        vm.prank(owner);
        verifier.pause();

        uint8[] memory types = new uint8[](1);
        types[0] = ProofTypes.COMPLIANCE;
        bytes[] memory proofs = new bytes[](1);
        proofs[0] = _dummyProof();
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = _complianceInputs();

        vm.expectRevert(Pausable.ContractPaused.selector);
        verifier.verifyProofBatch(types, proofs, inputs);
    }

    function test_pause_blocksVerifyProofAtVersion() public {
        vm.prank(owner);
        verifier.pause();

        vm.expectRevert(Pausable.ContractPaused.selector);
        verifier.verifyProofAtVersion(ProofTypes.COMPLIANCE, 1, _dummyProof(), _complianceInputs());
    }

    function test_pause_allowsGetVerifier() public {
        vm.prank(owner);
        verifier.pause();

        assertEq(verifier.getVerifier(ProofTypes.COMPLIANCE), address(passingVerifier));
    }

    function test_unpause_resumesVerifyProof() public {
        vm.startPrank(owner);
        verifier.pause();
        verifier.unpause();
        vm.stopPrank();

        assertTrue(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));
    }

    function test_pause_revert_notOwner() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        verifier.pause();
    }

    function test_pause_revert_alreadyPaused() public {
        vm.startPrank(owner);
        verifier.pause();
        vm.expectRevert(Pausable.ContractPaused.selector);
        verifier.pause();
        vm.stopPrank();
    }

    function test_unpause_revert_notPaused() public {
        vm.prank(owner);
        vm.expectRevert(Pausable.ContractNotPaused.selector);
        verifier.unpause();
    }

    function test_pause_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit Pausable.Paused(owner);
        verifier.pause();
    }

    function test_unpause_emitsEvent() public {
        vm.prank(owner);
        verifier.pause();

        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit Pausable.Unpaused(owner);
        verifier.unpause();
    }

    // -------------------------------------------------------------------------
    // Per-proof-type pause
    // -------------------------------------------------------------------------

    function test_pauseProofType_blocksVerifyProof() public {
        vm.prank(owner);
        verifier.pauseProofType(ProofTypes.COMPLIANCE);

        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.ProofTypePaused.selector, ProofTypes.COMPLIANCE));
        verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs());
    }

    function test_pauseProofType_allowsOtherTypes() public {
        vm.prank(owner);
        verifier.pauseProofType(ProofTypes.COMPLIANCE);

        // RISK_SCORE should still work
        assertTrue(verifier.verifyProof(ProofTypes.RISK_SCORE, _dummyProof(), _riskScoreInputs()));
    }

    function test_pauseProofType_blocksVerifyProofAtVersion() public {
        vm.prank(owner);
        verifier.pauseProofType(ProofTypes.COMPLIANCE);

        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.ProofTypePaused.selector, ProofTypes.COMPLIANCE));
        verifier.verifyProofAtVersion(ProofTypes.COMPLIANCE, 1, _dummyProof(), _complianceInputs());
    }

    function test_unpauseProofType_resumesVerification() public {
        vm.startPrank(owner);
        verifier.pauseProofType(ProofTypes.COMPLIANCE);
        verifier.unpauseProofType(ProofTypes.COMPLIANCE);
        vm.stopPrank();

        assertTrue(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));
    }

    function test_pauseProofType_revert_alreadyPaused() public {
        vm.startPrank(owner);
        verifier.pauseProofType(ProofTypes.COMPLIANCE);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.ProofTypePaused.selector, ProofTypes.COMPLIANCE));
        verifier.pauseProofType(ProofTypes.COMPLIANCE);
        vm.stopPrank();
    }

    function test_unpauseProofType_revert_notPaused() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.ProofTypeNotPaused.selector, ProofTypes.COMPLIANCE));
        verifier.unpauseProofType(ProofTypes.COMPLIANCE);
    }

    function test_pauseProofType_revert_notOwner() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        verifier.pauseProofType(ProofTypes.COMPLIANCE);
    }

    function test_pauseProofType_revert_invalidProofType() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x09));
        verifier.pauseProofType(0x09);
    }

    function test_isProofTypePaused() public {
        assertFalse(verifier.isProofTypePaused(ProofTypes.COMPLIANCE));
        vm.prank(owner);
        verifier.pauseProofType(ProofTypes.COMPLIANCE);
        assertTrue(verifier.isProofTypePaused(ProofTypes.COMPLIANCE));
    }

    function test_pauseProofType_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit XochiZKPVerifier.ProofTypePausedEvent(ProofTypes.COMPLIANCE, owner);
        verifier.pauseProofType(ProofTypes.COMPLIANCE);
    }

    function test_unpauseProofType_emitsEvent() public {
        vm.prank(owner);
        verifier.pauseProofType(ProofTypes.COMPLIANCE);

        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit XochiZKPVerifier.ProofTypeUnpausedEvent(ProofTypes.COMPLIANCE, owner);
        verifier.unpauseProofType(ProofTypes.COMPLIANCE);
    }

    // -------------------------------------------------------------------------
    // Ownership transfer cancellation
    // -------------------------------------------------------------------------

    function test_transferOwnership_emitsCancellation_whenPendingExists() public {
        address bob = makeAddr("bob");
        vm.startPrank(owner);
        verifier.transferOwnership(alice);

        vm.expectEmit(true, false, false, false);
        emit Ownable2Step.OwnershipTransferCancelled(alice);
        verifier.transferOwnership(bob);
        vm.stopPrank();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function _dummyProof() internal pure returns (bytes memory) {
        return new bytes(2144);
    }

    /// @dev 6 public inputs: jurisdiction_id, provider_set_hash, config_hash, timestamp, meets_threshold, submitter
    function _complianceInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(0)), // jurisdiction_id: EU
            bytes32(uint256(0xaabb)), // provider_set_hash
            bytes32(uint256(0xccdd)), // config_hash
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(1)), // meets_threshold: true
            bytes32(uint256(0xdead)) // submitter
        );
    }

    /// @dev 8 public inputs: proof_type, direction, bound_lower, bound_upper, result, config_hash, provider_set_hash, submitter
    function _riskScoreInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(1)), // proof_type: threshold
            bytes32(uint256(1)), // direction: GT
            bytes32(uint256(5000)), // bound_lower
            bytes32(uint256(0)), // bound_upper (unused for threshold)
            bytes32(uint256(1)), // result: true
            bytes32(uint256(0xccdd)), // config_hash
            bytes32(uint256(0xeeff)), // provider_set_hash
            bytes32(uint256(0xdead)) // submitter
        );
    }

    /// @dev 6 public inputs: analysis_type, result, reporting_threshold, time_window, tx_set_hash, submitter
    function _patternInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(1)), // analysis_type: structuring
            bytes32(uint256(1)), // result: clean
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(3600)), // time_window
            bytes32(uint256(0xeeff)), // tx_set_hash
            bytes32(uint256(0xdead)) // submitter
        );
    }

    /// @dev 6 public inputs: provider_id, credential_type, is_valid, merkle_root, current_timestamp, submitter
    function _attestationInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(42)), // provider_id
            bytes32(uint256(1)), // credential_type: KYC basic
            bytes32(uint256(1)), // is_valid: true
            bytes32(uint256(0xdead)), // merkle_root
            bytes32(uint256(1700000)), // current_timestamp
            bytes32(uint256(0xdead)) // submitter
        );
    }

    /// @dev 5 public inputs: merkle_root, set_id, timestamp, is_member, submitter
    function _membershipInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(0xabcd)), // merkle_root
            bytes32(uint256(1)), // set_id
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(1)), // is_member: true
            bytes32(uint256(0xdead)) // submitter
        );
    }

    /// @dev 5 public inputs: merkle_root, set_id, timestamp, is_non_member, submitter
    function _nonMembershipInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(0xabcd)), // merkle_root
            bytes32(uint256(1)), // set_id
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(1)), // is_non_member: true
            bytes32(uint256(0xdead)) // submitter
        );
    }
}
