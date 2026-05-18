// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {ERC8262Verifier} from "../src/ERC8262Verifier.sol";
import {IERC8262Verifier} from "../src/interfaces/IERC8262Verifier.sol";
import {IERC165} from "../src/interfaces/IERC165.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";
import {Ownable2Step} from "../src/libraries/Ownable2Step.sol";
import {AccessControl} from "../src/libraries/AccessControl.sol";
import {Pausable} from "../src/libraries/Pausable.sol";
import {ERC8262TestBase} from "./utils/ERC8262TestBase.sol";
import {StubVerifier, MutatingVerifier} from "./utils/TestStubs.sol";

contract ERC8262VerifierTest is ERC8262TestBase {
    ERC8262Verifier internal verifier;
    StubVerifier internal passingVerifier;
    StubVerifier internal failingVerifier;

    function setUp() public {
        verifier = new ERC8262Verifier(owner);
        passingVerifier = new StubVerifier(true);
        failingVerifier = new StubVerifier(false);
        _registerAllVerifiers(verifier, address(passingVerifier), false);
    }

    /// @dev Deploy a fresh StubVerifier (passes code existence check)
    function _newStub() internal returns (address) {
        return address(new StubVerifier(true));
    }

    /// @dev Upgrade a verifier via the timelock: propose, warp, execute
    function _upgradeVerifier(uint8 proofType, address newVerifier) internal {
        vm.prank(owner);
        verifier.proposeVerifier(proofType, newVerifier, newVerifier.codehash);
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
        new ERC8262Verifier(address(0));
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

        // 0x01..0x09 are valid (incl. COMPLIANCE_MULTI_SIGNED); 0x0a is the
        // next out-of-range type.
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x0a));
        verifier.verifyProof(0x0a, _dummyProof(), _complianceInputs());
    }

    function test_verifyProof_revert_verifierNotSet() public {
        ERC8262Verifier fresh = new ERC8262Verifier(owner);

        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.VerifierNotSet.selector, ProofTypes.COMPLIANCE));
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
        vm.expectRevert(ERC8262Verifier.EmptyBatch.selector);
        verifier.verifyProofBatch(new uint8[](0), new bytes[](0), new bytes[](0));
    }

    function test_verifyProofBatch_revert_batchTooLarge() public {
        uint256 size = verifier.MAX_BATCH_SIZE() + 1;
        uint8[] memory types = new uint8[](size);
        bytes[] memory proofs = new bytes[](size);
        bytes[] memory inputs = new bytes[](size);

        vm.expectRevert(ERC8262Verifier.BatchTooLarge.selector);
        verifier.verifyProofBatch(types, proofs, inputs);
    }

    function test_verifyProofBatch_revert_lengthMismatch() public {
        uint8[] memory types = new uint8[](2);
        bytes[] memory proofs = new bytes[](1);
        bytes[] memory inputs = new bytes[](2);

        vm.expectRevert(ERC8262Verifier.BatchLengthMismatch.selector);
        verifier.verifyProofBatch(types, proofs, inputs);
    }

    // -------------------------------------------------------------------------
    // Admin: setVerifierInitial
    // -------------------------------------------------------------------------

    function test_setVerifierInitial_revert_alreadySet() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.VerifierAlreadySet.selector, ProofTypes.COMPLIANCE));
        verifier.setVerifierInitial(ProofTypes.COMPLIANCE, address(passingVerifier));
    }

    function test_setVerifierInitial_fresh() public {
        ERC8262Verifier fresh = new ERC8262Verifier(owner);
        address newVerifier = _newStub();
        vm.prank(owner);
        fresh.setVerifierInitial(ProofTypes.COMPLIANCE, newVerifier);
        assertEq(fresh.getVerifier(ProofTypes.COMPLIANCE), newVerifier);
    }

    function test_setVerifierInitial_revert_notOwner() public {
        ERC8262Verifier fresh = new ERC8262Verifier(owner);
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        fresh.setVerifierInitial(ProofTypes.COMPLIANCE, address(passingVerifier));
    }

    function test_setVerifierInitial_revert_zeroAddress() public {
        ERC8262Verifier fresh = new ERC8262Verifier(owner);
        vm.prank(owner);
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        fresh.setVerifierInitial(ProofTypes.COMPLIANCE, address(0));
    }

    function test_setVerifierInitial_revert_invalidProofType() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x0a));
        verifier.setVerifierInitial(0x0a, address(passingVerifier));
    }

    function test_setVerifierInitial_revert_notAContract() public {
        ERC8262Verifier fresh = new ERC8262Verifier(owner);
        address eoa = makeAddr("eoa");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.NotAContract.selector, eoa));
        fresh.setVerifierInitial(ProofTypes.COMPLIANCE, eoa);
    }

    function test_proposeVerifier_revert_notAContract() public {
        address eoa = makeAddr("eoa");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.NotAContract.selector, eoa));
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, eoa, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // Codehash pinning (audit follow-up)
    // -------------------------------------------------------------------------

    function test_proposeVerifier_revert_codehashMismatch_atPropose() public {
        address newVerifier = _newStub();
        bytes32 wrongCodehash = keccak256("not-the-real-codehash");
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC8262Verifier.CodehashMismatch.selector, newVerifier, wrongCodehash, newVerifier.codehash
            )
        );
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier, wrongCodehash);
    }

    function test_executeVerifierUpdate_revert_codehashChangedMidWindow() public {
        // Propose against the real codehash. Mid-window, simulate a CREATE2
        // redeploy-with-different-bytecode at the same address by overwriting
        // the deployed code with vm.etch. Execute must revert.
        address newVerifier = _newStub();
        bytes32 originalCodehash = newVerifier.codehash;
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier, originalCodehash);

        bytes memory swappedCode = hex"600160005260206000f3"; // returns 1; nothing the router would accept
        vm.etch(newVerifier, swappedCode);
        bytes32 newCodehash = keccak256(swappedCode);
        assertEq(newVerifier.codehash, newCodehash);
        assertTrue(newCodehash != originalCodehash);

        vm.warp(block.timestamp + 24 hours);
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC8262Verifier.CodehashMismatch.selector, newVerifier, originalCodehash, newCodehash
            )
        );
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
    }

    function test_proposeAndExecute_succeeds_whenCodehashMatches() public {
        address newVerifier = _newStub();
        bytes32 ch = newVerifier.codehash;

        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier, ch);
        vm.warp(block.timestamp + 24 hours);
        vm.prank(owner);
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);

        assertEq(verifier.getVerifier(ProofTypes.COMPLIANCE), newVerifier);
    }

    // -------------------------------------------------------------------------
    // Admin: proposeVerifier / executeVerifierUpdate / cancelVerifierProposal
    // -------------------------------------------------------------------------

    function test_proposeVerifier_setsProposal() public {
        address newVerifier = _newStub();
        bytes32 ch = newVerifier.codehash;
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier, ch);

        (address proposed, uint256 readyAt, bytes32 pinned) = verifier.getPendingVerifier(ProofTypes.COMPLIANCE);
        assertEq(proposed, newVerifier);
        assertEq(readyAt, block.timestamp + 24 hours);
        assertEq(pinned, ch);
    }

    function test_executeVerifierUpdate_afterTimelock() public {
        address newVerifier = _newStub();
        _upgradeVerifier(ProofTypes.COMPLIANCE, newVerifier);
        assertEq(verifier.getVerifier(ProofTypes.COMPLIANCE), newVerifier);
    }

    function test_executeVerifierUpdate_revert_beforeTimelock() public {
        address newVerifier = _newStub();
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier, newVerifier.codehash);

        vm.warp(block.timestamp + 24 hours - 1);
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC8262Verifier.TimelockNotElapsed.selector, ProofTypes.COMPLIANCE, block.timestamp + 1
            )
        );
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
    }

    function test_executeVerifierUpdate_exactBoundary() public {
        address newVerifier = _newStub();
        uint256 proposeTime = block.timestamp;
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier, newVerifier.codehash);

        vm.warp(proposeTime + 24 hours);
        vm.prank(owner);
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
        assertEq(verifier.getVerifier(ProofTypes.COMPLIANCE), newVerifier);
    }

    function test_cancelVerifierProposal() public {
        address newVerifier = _newStub();
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier, newVerifier.codehash);

        vm.prank(owner);
        verifier.cancelVerifierProposal(ProofTypes.COMPLIANCE);

        (address proposed, uint256 readyAt, bytes32 pinned) = verifier.getPendingVerifier(ProofTypes.COMPLIANCE);
        assertEq(proposed, address(0));
        assertEq(readyAt, 0);
        assertEq(pinned, bytes32(0));
    }

    function test_cancelVerifierProposal_revert_noPending() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.NoPendingProposal.selector, ProofTypes.COMPLIANCE));
        verifier.cancelVerifierProposal(ProofTypes.COMPLIANCE);
    }

    function test_proposeVerifier_revert_alreadyPending() public {
        address v1 = _newStub();
        address v2 = _newStub();
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, v1, v1.codehash);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.ProposalAlreadyPending.selector, ProofTypes.COMPLIANCE));
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, v2, v2.codehash);
    }

    function test_executeVerifierUpdate_revert_noPending() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.NoPendingProposal.selector, ProofTypes.COMPLIANCE));
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
    }

    function test_executeVerifierUpdate_emitsEvent() public {
        address newVerifier = _newStub();
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier, newVerifier.codehash);

        vm.warp(block.timestamp + 24 hours);
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit ERC8262Verifier.VerifierUpdated(ProofTypes.COMPLIANCE, address(passingVerifier), newVerifier);
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
    }

    function test_proposeVerifier_emitsEvent() public {
        address newVerifier = _newStub();
        bytes32 ch = newVerifier.codehash;
        uint256 readyAt = block.timestamp + 24 hours;
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit ERC8262Verifier.VerifierProposed(ProofTypes.COMPLIANCE, newVerifier, ch, readyAt);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, newVerifier, ch);
    }

    function test_getPendingVerifier_noPending() public view {
        (address proposed, uint256 readyAt, bytes32 pinned) = verifier.getPendingVerifier(ProofTypes.COMPLIANCE);
        assertEq(proposed, address(0));
        assertEq(readyAt, 0);
        assertEq(pinned, bytes32(0));
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
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 0));
        verifier.getVerifierAtVersion(ProofTypes.COMPLIANCE, 0);

        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 99));
        verifier.getVerifierAtVersion(ProofTypes.COMPLIANCE, 99);
    }

    function test_getVerifierVersion_noVerifierSet() public {
        ERC8262Verifier fresh = new ERC8262Verifier(owner);
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
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.VersionRevoked.selector, ProofTypes.COMPLIANCE, 1));
        verifier.verifyProofAtVersion(ProofTypes.COMPLIANCE, 1, _dummyProof(), _complianceInputs());
    }

    function test_revokeVerifierVersion_emitsEvent() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit ERC8262Verifier.VerifierVersionRevoked(ProofTypes.COMPLIANCE, 1, address(passingVerifier));
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);
    }

    function test_revokeVerifierVersion_revert_currentVersion() public {
        // Only v1 exists, can't revoke current
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(ERC8262Verifier.CannotRevokeCurrentVersion.selector, ProofTypes.COMPLIANCE)
        );
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);
    }

    function test_revokeVerifierVersion_revert_alreadyRevoked() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        vm.prank(owner);
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.AlreadyRevoked.selector, ProofTypes.COMPLIANCE, 1));
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);
    }

    function test_revokeVerifierVersion_revert_invalidVersion() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 0));
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 0);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 99));
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
        emit ERC8262Verifier.VersionRevocationProposed(ProofTypes.COMPLIANCE, 1, readyAt);
        vm.prank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        assertEq(verifier.getPendingRevocation(ProofTypes.COMPLIANCE, 1), readyAt);
        // Version is NOT yet revoked
        assertFalse(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 1));
    }

    function test_proposeVersionRevocation_revert_currentVersion() public {
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(ERC8262Verifier.CannotRevokeCurrentVersion.selector, ProofTypes.COMPLIANCE)
        );
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
    }

    function test_proposeVersionRevocation_revert_alreadyRevoked() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));
        vm.prank(owner);
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.AlreadyRevoked.selector, ProofTypes.COMPLIANCE, 1));
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
    }

    function test_proposeVersionRevocation_revert_alreadyPending() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        vm.startPrank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.ProposalAlreadyPending.selector, ProofTypes.COMPLIANCE));
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
        vm.stopPrank();
    }

    function test_proposeVersionRevocation_revert_invalidVersion() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 0));
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 0);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 99));
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
            abi.encodeWithSelector(ERC8262Verifier.TimelockNotElapsed.selector, ProofTypes.COMPLIANCE, readyAt)
        );
        vm.prank(owner);
        verifier.executeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        // Just before ready
        vm.warp(readyAt - 1);
        vm.expectRevert(
            abi.encodeWithSelector(ERC8262Verifier.TimelockNotElapsed.selector, ProofTypes.COMPLIANCE, readyAt)
        );
        vm.prank(owner);
        verifier.executeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        // At ready time -- success
        vm.warp(readyAt);
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit ERC8262Verifier.VerifierVersionRevoked(ProofTypes.COMPLIANCE, 1, address(passingVerifier));
        verifier.executeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        assertTrue(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 1));
        // Pending state cleared
        assertEq(verifier.getPendingRevocation(ProofTypes.COMPLIANCE, 1), 0);
    }

    function test_executeVersionRevocation_revert_noPendingProposal() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.NoPendingProposal.selector, ProofTypes.COMPLIANCE));
        verifier.executeVersionRevocation(ProofTypes.COMPLIANCE, 1);
    }

    function test_cancelVersionRevocation_succeeds() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        vm.prank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit ERC8262Verifier.VersionRevocationCancelled(ProofTypes.COMPLIANCE, 1);
        verifier.cancelVersionRevocation(ProofTypes.COMPLIANCE, 1);

        assertEq(verifier.getPendingRevocation(ProofTypes.COMPLIANCE, 1), 0);
        assertFalse(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 1));

        // After cancellation, can re-propose
        vm.prank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
    }

    function test_cancelVersionRevocation_revert_noPendingProposal() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.NoPendingProposal.selector, ProofTypes.COMPLIANCE));
        verifier.cancelVersionRevocation(ProofTypes.COMPLIANCE, 1);
    }

    function test_cancelVersionRevocation_revert_notOwner() public {
        _upgradeVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));
        vm.prank(owner);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.NotCancelAuthorized.selector, alice));
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
        // 0x01..0x09 are valid (incl. COMPLIANCE_MULTI_SIGNED); 0x0a+ are not.
        vm.assume(proofType == 0 || proofType > 9);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, proofType));
        verifier.verifyProof(proofType, _dummyProof(), _complianceInputs());
    }

    function testFuzz_proposeVerifier_revert_invalidProofType(uint8 proofType) public {
        vm.assume(proofType == 0 || proofType > 9);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, proofType));
        verifier.proposeVerifier(proofType, address(passingVerifier), address(passingVerifier).codehash);
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

        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.ProofTypePaused.selector, ProofTypes.COMPLIANCE));
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

        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.ProofTypePaused.selector, ProofTypes.COMPLIANCE));
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
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.ProofTypePaused.selector, ProofTypes.COMPLIANCE));
        verifier.pauseProofType(ProofTypes.COMPLIANCE);
        vm.stopPrank();
    }

    function test_unpauseProofType_revert_notPaused() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.ProofTypeNotPaused.selector, ProofTypes.COMPLIANCE));
        verifier.unpauseProofType(ProofTypes.COMPLIANCE);
    }

    function test_pauseProofType_revert_notOwner() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        verifier.pauseProofType(ProofTypes.COMPLIANCE);
    }

    function test_pauseProofType_revert_invalidProofType() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x0a));
        verifier.pauseProofType(0x0a);
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
        emit ERC8262Verifier.ProofTypePausedEvent(ProofTypes.COMPLIANCE, owner);
        verifier.pauseProofType(ProofTypes.COMPLIANCE);
    }

    function test_unpauseProofType_emitsEvent() public {
        vm.prank(owner);
        verifier.pauseProofType(ProofTypes.COMPLIANCE);

        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit ERC8262Verifier.ProofTypeUnpausedEvent(ProofTypes.COMPLIANCE, owner);
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
    // EIP-165
    // -------------------------------------------------------------------------

    function test_supportsInterface_self() public view {
        assertTrue(verifier.supportsInterface(type(IERC8262Verifier).interfaceId));
    }

    function test_supportsInterface_erc165() public view {
        assertTrue(verifier.supportsInterface(type(IERC165).interfaceId));
    }

    function test_supportsInterface_invalidSelector_returnsFalse() public view {
        assertFalse(verifier.supportsInterface(0xffffffff));
    }

    function test_supportsInterface_unknownSelector_returnsFalse() public view {
        assertFalse(verifier.supportsInterface(0xdeadbeef));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

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

    /// @dev 7 public inputs: analysis_type, result, reporting_threshold, time_window,
    ///      tx_set_hash, submitter, settlement_root (audit H-1)
    function _patternInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(1)), // analysis_type: structuring
            bytes32(uint256(1)), // result: clean
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(3600)), // time_window
            bytes32(uint256(0xeeff)), // tx_set_hash
            bytes32(uint256(0xdead)), // submitter
            bytes32(0) // settlement_root (audit H-1)
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
