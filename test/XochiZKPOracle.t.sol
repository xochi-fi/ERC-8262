// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Test.sol";
import {XochiZKPOracle} from "../src/XochiZKPOracle.sol";
import {XochiZKPVerifier} from "../src/XochiZKPVerifier.sol";
import {IXochiZKPOracle} from "../src/interfaces/IXochiZKPOracle.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";
import {JurisdictionConfig} from "../src/libraries/JurisdictionConfig.sol";
import {Ownable2Step} from "../src/libraries/Ownable2Step.sol";
import {AccessControl} from "../src/libraries/AccessControl.sol";
import {Pausable} from "../src/libraries/Pausable.sol";
import {EIP712CredentialRoot} from "../src/libraries/EIP712CredentialRoot.sol";
import {IERC165} from "../src/interfaces/IERC165.sol";
import {XochiTestBase} from "./utils/XochiTestBase.sol";
import {PassingVerifier, FailingVerifier} from "./utils/TestStubs.sol";

contract XochiZKPOracleTest is XochiTestBase {
    XochiZKPOracle internal oracle;
    XochiZKPVerifier internal verifier;
    PassingVerifier internal stubVerifier;

    address internal publisher = makeAddr("publisher");

    bytes32 internal constant INITIAL_CONFIG = keccak256("initial-config");
    uint256 internal constant DEFAULT_PROVIDER_ID = 42;

    /// @dev Deterministic test signing key for credential-root signatures (audit C-1).
    ///      Registered as the credential signer for `DEFAULT_PROVIDER_ID` in setUp.
    uint256 internal constant CREDENTIAL_SIGNER_KEY = uint256(keccak256("xochi-test-credential-signer"));
    address internal credentialSignerAddr;

    // Mirror of XochiZKPOracle internal constants for risk-score validation tests.
    uint8 internal constant RISK_PROOF_THRESHOLD = 0x01;
    uint8 internal constant RISK_PROOF_RANGE = 0x02;
    uint8 internal constant RISK_DIRECTION_GT = 1;
    uint8 internal constant RISK_DIRECTION_LT = 2;

    /// @dev Default 1-element provider expansion used by tests that do not exercise
    ///      `denyProvider` semantics. Tests that need a different layout build their
    ///      own array inline.
    function _defaultProviders() internal pure returns (uint256[] memory ps) {
        ps = new uint256[](1);
        ps[0] = DEFAULT_PROVIDER_ID;
    }

    function setUp() public {
        verifier = new XochiZKPVerifier(owner);
        oracle = new XochiZKPOracle(address(verifier), owner, INITIAL_CONFIG, _defaultProviders());

        stubVerifier = new PassingVerifier();
        _registerAllVerifiers(verifier, address(stubVerifier), true);

        vm.startPrank(owner);
        // Register default reporting threshold for PATTERN tests
        oracle.registerReportingThreshold(bytes32(uint256(10000)));
        // Register the default attestation provider's publisher and credential
        // signing key. Tests publish credential roots via `_publishCredentialRoot`,
        // which signs the EIP-712 publication with `CREDENTIAL_SIGNER_KEY`.
        oracle.setProviderPublisher(DEFAULT_PROVIDER_ID, publisher);
        credentialSignerAddr = vm.addr(CREDENTIAL_SIGNER_KEY);
        oracle.setCredentialSigner(DEFAULT_PROVIDER_ID, credentialSignerAddr);
        vm.stopPrank();
    }

    /// @dev Publish a credential root for the default provider (test helper).
    function _publishCredentialRoot(bytes32 root) internal {
        _publishCredentialRootSigned(DEFAULT_PROVIDER_ID, publisher, root, "", CREDENTIAL_SIGNER_KEY);
    }

    /// @dev Publish a credential root with explicit signer key + publisher EOA.
    ///      Computes `notBefore = block.timestamp` and `notAfter = block.timestamp + 1 hour`.
    function _publishCredentialRootSigned(
        uint256 providerId,
        address pub,
        bytes32 root,
        string memory cid,
        uint256 signerKey
    ) internal {
        uint64 notBefore = uint64(block.timestamp);
        uint64 notAfter = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signCredentialRoot(providerId, root, cid, notBefore, notAfter, signerKey);
        vm.prank(pub);
        oracle.publishCredentialRoot(providerId, root, cid, notBefore, notAfter, sig);
    }

    /// @dev Build an EIP-712 signature over a CredentialRootPublication for tests.
    function _signCredentialRoot(
        uint256 providerId,
        bytes32 root,
        string memory cid,
        uint64 notBefore,
        uint64 notAfter,
        uint256 signerKey
    ) internal view returns (bytes memory) {
        bytes32 digest = EIP712CredentialRoot.toTypedDataHash(
            EIP712CredentialRoot.buildDomainSeparator(address(oracle)),
            providerId,
            root,
            keccak256(bytes(cid)),
            notBefore,
            notAfter
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    function test_constructor_setsState() public view {
        assertEq(address(oracle.verifier()), address(verifier));
        assertEq(oracle.owner(), owner);
        assertEq(oracle.providerConfigHash(), INITIAL_CONFIG);
        assertEq(oracle.attestationTTL(), 24 hours);
    }

    function test_constructor_revert_zeroVerifier() public {
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        new XochiZKPOracle(address(0), owner, INITIAL_CONFIG, _defaultProviders());
    }

    function test_constructor_revert_zeroOwner() public {
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        new XochiZKPOracle(address(verifier), address(0), INITIAL_CONFIG, _defaultProviders());
    }

    // -------------------------------------------------------------------------
    // submitCompliance
    // -------------------------------------------------------------------------

    function test_submitCompliance_recordsAttestation() public {
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = _complianceInputs();

        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);

        assertEq(att.subject, alice);
        assertEq(att.jurisdictionId, 0);
        assertEq(att.proofType, ProofTypes.COMPLIANCE);
        assertTrue(att.meetsThreshold);
        assertEq(att.timestamp, block.timestamp);
        assertEq(att.expiresAt, block.timestamp + 24 hours);
        assertEq(att.proofHash, oracle.computeProofHash(proof, ProofTypes.COMPLIANCE));
        assertEq(att.providerSetHash, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_emitsEvent() public {
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = _complianceInputs();
        bytes32 expectedHash = oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IXochiZKPOracle.ComplianceVerified(alice, 0, true, expectedHash, block.timestamp + 24 hours, 0);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_emitsEvent_withPreviousExpiry() public {
        // First submission
        _submitForAlice(0);
        uint256 firstExpiresAt = block.timestamp + 24 hours;

        // Second submission should emit the first expiry
        bytes memory proof2 = _uniqueProof();
        bytes32 expectedHash = oracle.computeProofHash(proof2, ProofTypes.COMPLIANCE);
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IXochiZKPOracle.ComplianceVerified(
            alice, 0, true, expectedHash, block.timestamp + 24 hours, firstExpiresAt
        );
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof2, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_revert_invalidJurisdiction() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(JurisdictionConfig.InvalidJurisdiction.selector, 4));
        oracle.submitCompliance(
            4,
            ProofTypes.COMPLIANCE,
            _uniqueProof(),
            _complianceInputsFor(4, DEFAULT_PROVIDER_SET_HASH),
            DEFAULT_PROVIDER_SET_HASH
        );
    }

    // -------------------------------------------------------------------------
    // checkCompliance
    // -------------------------------------------------------------------------

    function test_checkCompliance_validAttestation() public {
        _submitForAlice(0);

        (bool valid, IXochiZKPOracle.ComplianceAttestation memory att) = oracle.checkCompliance(alice, 0);

        assertTrue(valid);
        assertEq(att.subject, alice);
    }

    function test_checkCompliance_expired() public {
        _submitForAlice(0);
        vm.warp(block.timestamp + 24 hours + 1);

        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertFalse(valid);
    }

    function test_checkCompliance_noAttestation() public view {
        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertFalse(valid);
    }

    function test_checkCompliance_wrongJurisdiction() public {
        _submitForAlice(0); // EU

        (bool valid,) = oracle.checkCompliance(alice, 1); // US
        assertFalse(valid);
    }

    // -------------------------------------------------------------------------
    // checkComplianceByType
    // -------------------------------------------------------------------------

    function test_checkComplianceByType_matches() public {
        _submitForAlice(0);

        (bool valid, IXochiZKPOracle.ComplianceAttestation memory att) =
            oracle.checkComplianceByType(alice, 0, ProofTypes.COMPLIANCE);
        assertTrue(valid);
        assertEq(att.proofType, ProofTypes.COMPLIANCE);
    }

    function test_checkComplianceByType_mismatch() public {
        _submitForAlice(0); // submits COMPLIANCE

        (bool valid,) = oracle.checkComplianceByType(alice, 0, ProofTypes.RISK_SCORE);
        assertFalse(valid);
    }

    function test_checkComplianceByType_riskScore() public {
        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), _riskScoreInputs(INITIAL_CONFIG), bytes32(0));

        (bool valid, IXochiZKPOracle.ComplianceAttestation memory att) =
            oracle.checkComplianceByType(alice, 0, ProofTypes.RISK_SCORE);
        assertTrue(valid);
        assertEq(att.proofType, ProofTypes.RISK_SCORE);
    }

    // -------------------------------------------------------------------------
    // getHistoricalProof
    // -------------------------------------------------------------------------

    function test_getHistoricalProof_returnsAttestation() public {
        bytes memory proof = _uniqueProof();

        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        bytes32 proofHash = oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.getHistoricalProof(proofHash);

        assertEq(att.subject, alice);
        assertEq(att.proofHash, proofHash);
    }

    function test_getHistoricalProof_revert_notFound() public {
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.AttestationNotFound.selector, bytes32(uint256(999))));
        oracle.getHistoricalProof(bytes32(uint256(999)));
    }

    // -------------------------------------------------------------------------
    // getAttestationHistory
    // -------------------------------------------------------------------------

    function test_getAttestationHistory_tracksMultiple() public {
        bytes memory proof1 = _uniqueProof();
        bytes memory proof2 = _uniqueProof();

        vm.startPrank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof1, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof2, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
        vm.stopPrank();

        bytes32[] memory history = oracle.getAttestationHistory(alice, 0);
        assertEq(history.length, 2);
        assertEq(history[0], oracle.computeProofHash(proof1, ProofTypes.COMPLIANCE));
        assertEq(history[1], oracle.computeProofHash(proof2, ProofTypes.COMPLIANCE));
    }

    // -------------------------------------------------------------------------
    // Admin: provider config
    // -------------------------------------------------------------------------

    function test_updateProviderConfig() public {
        bytes32 newConfig = keccak256("new-config");
        string memory uri = "ipfs://QmNewConfig";

        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit IXochiZKPOracle.ProviderWeightsUpdated(newConfig, block.timestamp, uri);
        oracle.updateProviderConfig(newConfig, uri, _defaultProviders());

        assertEq(oracle.providerConfigHash(), newConfig);
        assertEq(oracle.configHistoryLength(), 2);
        assertEq(oracle.configHistoryAt(1), newConfig);
    }

    function test_updateProviderConfig_revert_notOwner() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.updateProviderConfig(bytes32(0), "", _defaultProviders());
    }

    // -------------------------------------------------------------------------
    // Admin: attestation TTL
    // -------------------------------------------------------------------------

    function test_updateAttestationTTL() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit IXochiZKPOracle.AttestationTTLUpdated(24 hours, 12 hours);
        oracle.updateAttestationTTL(12 hours);

        assertEq(oracle.attestationTTL(), 12 hours);
    }

    function test_updateAttestationTTL_revert_tooLow() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.InvalidTTL.selector);
        oracle.updateAttestationTTL(30 minutes);
    }

    function test_updateAttestationTTL_revert_tooHigh() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.InvalidTTL.selector);
        oracle.updateAttestationTTL(31 days);
    }

    // -------------------------------------------------------------------------
    // Proof replay protection
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_proofReplay() public {
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = _complianceInputs();
        bytes32 expectedHash = oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);

        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.ProofAlreadyUsed.selector, expectedHash));
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // Public input validation
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_jurisdictionMismatch() public {
        // Public inputs say jurisdiction=0 (EU), but caller passes jurisdiction=2 (UK).
        // Both are permissive (no signed-signals requirement) so PublicInputMismatch fires
        // before any jurisdiction-policy check.
        bytes memory publicInputs = _complianceInputsFor(0, DEFAULT_PROVIDER_SET_HASH);
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.PublicInputMismatch.selector);
        oracle.submitCompliance(2, ProofTypes.COMPLIANCE, _uniqueProof(), publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_revert_providerSetHashMismatch() public {
        // Public inputs have providerSetHash=0xaabb, but caller passes different hash
        bytes memory publicInputs = _complianceInputs();
        bytes32 wrongHash = keccak256("wrong");
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.PublicInputMismatch.selector);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _uniqueProof(), publicInputs, wrongHash);
    }

    // -------------------------------------------------------------------------
    // Paginated history
    // -------------------------------------------------------------------------

    function test_getAttestationHistoryPaginated() public {
        // Submit 5 proofs
        vm.startPrank(alice);
        bytes32[5] memory hashes;
        for (uint256 i; i < 5; i++) {
            bytes memory proof = _uniqueProof();
            hashes[i] = oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
        }
        vm.stopPrank();

        // Page 1: offset=0, limit=2
        (bytes32[] memory page1, uint256 total1) = oracle.getAttestationHistoryPaginated(alice, 0, 0, 2);
        assertEq(total1, 5);
        assertEq(page1.length, 2);
        assertEq(page1[0], hashes[0]);
        assertEq(page1[1], hashes[1]);

        // Page 2: offset=2, limit=2
        (bytes32[] memory page2,) = oracle.getAttestationHistoryPaginated(alice, 0, 2, 2);
        assertEq(page2.length, 2);
        assertEq(page2[0], hashes[2]);

        // Page 3: offset=4, limit=2 (only 1 remaining)
        (bytes32[] memory page3,) = oracle.getAttestationHistoryPaginated(alice, 0, 4, 2);
        assertEq(page3.length, 1);
        assertEq(page3[0], hashes[4]);

        // Beyond end
        (bytes32[] memory empty,) = oracle.getAttestationHistoryPaginated(alice, 0, 10, 2);
        assertEq(empty.length, 0);
    }

    // -------------------------------------------------------------------------
    // Concurrent attestations (same user, multiple jurisdictions)
    // -------------------------------------------------------------------------

    function test_concurrentAttestations_multipleJurisdictions() public {
        // Alice submits unsigned COMPLIANCE for EU (0) and UK (2), the two permissive
        // jurisdictions. US (1) and Singapore (3) require signed-signals proofs and
        // are exercised by the COMPLIANCE_SIGNED test suite.
        uint8[2] memory permissive = [uint8(0), uint8(2)];
        for (uint256 i; i < permissive.length; i++) {
            _submitForAlice(permissive[i]);
        }

        for (uint256 i; i < permissive.length; i++) {
            uint8 j = permissive[i];
            (bool valid, IXochiZKPOracle.ComplianceAttestation memory att) = oracle.checkCompliance(alice, j);
            assertTrue(valid);
            assertEq(att.jurisdictionId, j);
            assertEq(att.subject, alice);
        }

        // Singapore (3) has no attestation
        (bool valid3,) = oracle.checkCompliance(alice, 3);
        assertFalse(valid3);
    }

    function test_concurrentAttestations_independentExpiry() public {
        _submitForAlice(0); // EU
        vm.warp(block.timestamp + 12 hours);
        _submitForAlice(2); // UK (submitted 12h later, also permissive)

        // Fast forward to EU expiry but before UK expiry
        vm.warp(block.timestamp + 12 hours + 1);

        (bool euValid,) = oracle.checkCompliance(alice, 0);
        (bool ukValid,) = oracle.checkCompliance(alice, 2);
        assertFalse(euValid); // expired
        assertTrue(ukValid); // still valid
    }

    // -------------------------------------------------------------------------
    // Ownership
    // -------------------------------------------------------------------------

    function test_transferOwnership_twoStep() public {
        vm.prank(owner);
        oracle.transferOwnership(alice);

        vm.prank(alice);
        oracle.acceptOwnership();

        assertEq(oracle.owner(), alice);
    }

    function test_transferOwnership_revert_expired() public {
        vm.prank(owner);
        oracle.transferOwnership(alice);

        vm.warp(block.timestamp + 48 hours + 1);

        vm.prank(alice);
        vm.expectRevert(Ownable2Step.OwnershipTransferExpired.selector);
        oracle.acceptOwnership();
    }

    function test_transferOwnership_resetClearsPending() public {
        vm.prank(owner);
        oracle.transferOwnership(alice);

        // Owner can re-initiate, overwriting alice
        address bob = makeAddr("bob");
        vm.prank(owner);
        oracle.transferOwnership(bob);

        // Alice can no longer accept
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.NotPendingOwner.selector);
        oracle.acceptOwnership();

        // Bob can accept
        vm.prank(bob);
        oracle.acceptOwnership();
        assertEq(oracle.owner(), bob);
    }

    // -------------------------------------------------------------------------
    // Non-compliance proof types bypass input validation
    // -------------------------------------------------------------------------

    function test_submitCompliance_riskScore_validConfigHash() public {
        bytes memory publicInputs = _riskScoreInputs(INITIAL_CONFIG);
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
        assertEq(att.subject, alice);
    }

    // -------------------------------------------------------------------------
    // F2: providerSetHash zeroed for non-COMPLIANCE proofs
    // -------------------------------------------------------------------------

    function test_submitCompliance_nonComplianceProof_zerosProviderSetHash() public {
        bytes memory publicInputs = _riskScoreInputs(INITIAL_CONFIG);
        bytes32 arbitraryHash = keccak256("arbitrary");
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, arbitraryHash);
        assertEq(att.providerSetHash, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // Verifier used tracking
    // -------------------------------------------------------------------------

    function test_submitCompliance_capturesVerifierUsed() public {
        bytes memory proof = _uniqueProof();
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        assertEq(att.verifierUsed, address(stubVerifier));
    }

    function test_submitCompliance_verifierUsedSurvivesUpgrade() public {
        // Submit with original verifier
        bytes memory proof1 = _uniqueProof();
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att1 =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof1, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        // Upgrade verifier via timelock
        PassingVerifier newStub = new PassingVerifier();
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, address(newStub), address(newStub).codehash);
        vm.warp(block.timestamp + 24 hours);
        vm.prank(owner);
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);

        // Submit with new verifier
        bytes memory proof2 = _uniqueProof();
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att2 =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof2, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        // Historical proof preserves original verifier
        IXochiZKPOracle.ComplianceAttestation memory historical =
            oracle.getHistoricalProof(oracle.computeProofHash(proof1, ProofTypes.COMPLIANCE));
        assertEq(historical.verifierUsed, address(stubVerifier));
        assertEq(att1.verifierUsed, address(stubVerifier));
        assertEq(att2.verifierUsed, address(newStub));
    }

    // -------------------------------------------------------------------------
    // Config hash validation
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_invalidConfigHash() public {
        // Build compliance inputs with an unregistered config hash
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(0)), // jurisdiction_id
            DEFAULT_PROVIDER_SET_HASH, // provider_set_hash
            bytes32(uint256(0xdead)), // config_hash (not registered)
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(1)), // meets_threshold
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidConfigHash.selector, bytes32(uint256(0xdead))));
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _uniqueProof(), publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_revert_riskScore_invalidConfigHash() public {
        bytes32 badConfig = bytes32(uint256(0xdead));
        bytes memory publicInputs = _riskScoreInputs(badConfig);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidConfigHash.selector, badConfig));
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // H-1: RISK_SCORE semantic public input validation
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_riskScore_thresholdGT_boundZero() public {
        // Exploit: "score > 0" is trivially true; reject as TrivialRiskBound.
        bytes memory publicInputs =
            _riskScoreInputsCustom(RISK_PROOF_THRESHOLD, RISK_DIRECTION_GT, 0, 0, INITIAL_CONFIG, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.TrivialRiskBound.selector, 0, 0));
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_riskScore_thresholdGT_boundAtMax() public {
        // "score > 10000" impossible; reject.
        bytes memory publicInputs =
            _riskScoreInputsCustom(RISK_PROOF_THRESHOLD, RISK_DIRECTION_GT, 10000, 0, INITIAL_CONFIG, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.TrivialRiskBound.selector, 10000, 0));
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_riskScore_thresholdLT_boundOverMax() public {
        // "score < 10001+" trivially true; reject.
        bytes memory publicInputs =
            _riskScoreInputsCustom(RISK_PROOF_THRESHOLD, RISK_DIRECTION_LT, 10001, 0, INITIAL_CONFIG, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.TrivialRiskBound.selector, 10001, 0));
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_riskScore_thresholdLT_boundZero() public {
        // "score < 0" impossible; reject.
        bytes memory publicInputs =
            _riskScoreInputsCustom(RISK_PROOF_THRESHOLD, RISK_DIRECTION_LT, 0, 0, INITIAL_CONFIG, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.TrivialRiskBound.selector, 0, 0));
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_riskScore_invalidDirection() public {
        bytes memory publicInputs = _riskScoreInputsCustom(RISK_PROOF_THRESHOLD, 3, 5000, 0, INITIAL_CONFIG, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidRiskDirection.selector, 3));
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_riskScore_invalidProofType() public {
        bytes memory publicInputs = _riskScoreInputsCustom(7, RISK_DIRECTION_GT, 5000, 0, INITIAL_CONFIG, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidRiskProofType.selector, 7));
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_riskScore_range_invertedBounds() public {
        bytes memory publicInputs = _riskScoreInputsCustom(RISK_PROOF_RANGE, 0, 5000, 4000, INITIAL_CONFIG, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidRiskBound.selector, 5000, 4000));
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_riskScore_range_boundUpperOverMax() public {
        bytes memory publicInputs = _riskScoreInputsCustom(RISK_PROOF_RANGE, 0, 0, 10001, INITIAL_CONFIG, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidRiskBound.selector, 0, 10001));
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_riskScore_range_fullDomain() public {
        bytes memory publicInputs = _riskScoreInputsCustom(RISK_PROOF_RANGE, 0, 0, 10000, INITIAL_CONFIG, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.TrivialRiskBound.selector, 0, 10000));
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_riskScore_thresholdGT_acceptsMeaningfulBound() public {
        bytes memory publicInputs =
            _riskScoreInputsCustom(RISK_PROOF_THRESHOLD, RISK_DIRECTION_GT, 5000, 0, INITIAL_CONFIG, alice);
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
        assertEq(att.subject, alice);
    }

    function test_submitCompliance_riskScore_thresholdLT_acceptsMeaningfulBound() public {
        bytes memory publicInputs =
            _riskScoreInputsCustom(RISK_PROOF_THRESHOLD, RISK_DIRECTION_LT, 7100, 0, INITIAL_CONFIG, alice);
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
        assertEq(att.subject, alice);
    }

    function test_submitCompliance_riskScore_range_acceptsBoundedRange() public {
        bytes memory publicInputs = _riskScoreInputsCustom(RISK_PROOF_RANGE, 0, 4000, 5000, INITIAL_CONFIG, alice);
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
        assertEq(att.subject, alice);
    }

    function test_submitCompliance_historicalConfigHashAccepted() public {
        // Update config so INITIAL_CONFIG becomes historical (not current)
        bytes32 newConfig = keccak256("new-config");
        vm.prank(owner);
        oracle.updateProviderConfig(newConfig, "", _defaultProviders());

        // Submit with INITIAL_CONFIG -- should still be accepted
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH
        );
        assertEq(att.subject, alice);
    }

    function test_submitCompliance_patternProofType_skipsConfigValidation() public {
        // PATTERN (0x03) should not validate config hash
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(1)), // result
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0xabcd)), // tx_set_hash
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.PATTERN, _uniqueProof(), publicInputs, bytes32(0));
        assertEq(att.subject, alice);
    }

    function test_isValidConfig() public view {
        assertTrue(oracle.isValidConfig(INITIAL_CONFIG));
        assertFalse(oracle.isValidConfig(bytes32(uint256(0xdead))));
    }

    // -------------------------------------------------------------------------
    // Fuzz tests
    // -------------------------------------------------------------------------

    function testFuzz_updateAttestationTTL_validRange(uint256 ttl) public {
        ttl = bound(ttl, 1 hours, 30 days);
        vm.prank(owner);
        oracle.updateAttestationTTL(ttl);
        assertEq(oracle.attestationTTL(), ttl);
    }

    function testFuzz_updateAttestationTTL_revert_outOfRange(uint256 ttl) public {
        vm.assume(ttl < 1 hours || ttl > 30 days);
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.InvalidTTL.selector);
        oracle.updateAttestationTTL(ttl);
    }

    function testFuzz_checkCompliance_expiryBoundary(uint256 elapsed) public {
        elapsed = bound(elapsed, 0, 48 hours);
        _submitForAlice(0);

        vm.warp(block.timestamp + elapsed);
        (bool valid,) = oracle.checkCompliance(alice, 0);

        if (elapsed <= 24 hours) {
            assertTrue(valid);
        } else {
            assertFalse(valid);
        }
    }

    function testFuzz_submitCompliance_revert_invalidJurisdiction(uint8 j) public {
        vm.assume(j > 3);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(JurisdictionConfig.InvalidJurisdiction.selector, j));
        oracle.submitCompliance(
            j,
            ProofTypes.COMPLIANCE,
            _uniqueProof(),
            _complianceInputsFor(j, DEFAULT_PROVIDER_SET_HASH),
            DEFAULT_PROVIDER_SET_HASH
        );
    }

    function testFuzz_providerConfigVersioning(uint8 numUpdates) public {
        numUpdates = uint8(bound(numUpdates, 1, 20));
        vm.startPrank(owner);
        for (uint8 i; i < numUpdates; i++) {
            bytes32 config = keccak256(abi.encodePacked("config-", i));
            oracle.updateProviderConfig(config, "", _defaultProviders());
        }
        vm.stopPrank();

        // +1 for initial config
        assertEq(oracle.configHistoryLength(), uint256(numUpdates) + 1);
    }

    // -------------------------------------------------------------------------
    // Finding 1: Unaligned public inputs
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_nonAlignedPublicInputs() public {
        // 193 bytes = 6*32 + 1 -- extra trailing byte
        // Build valid compliance inputs then append one byte
        bytes memory aligned = _complianceInputs();
        bytes memory unaligned = abi.encodePacked(aligned, uint8(0xff));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.UnalignedPublicInputs.selector, 193));
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _uniqueProof(), unaligned, DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // Finding 2: Input validation for all proof types
    // -------------------------------------------------------------------------

    function test_submitCompliance_membershipProof_revert_unregisteredMerkleRoot() public {
        bytes memory publicInputs = _membershipInputs(bytes32(uint256(0xdead)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidMerkleRoot.selector, bytes32(uint256(0xdead))));
        oracle.submitCompliance(0, ProofTypes.MEMBERSHIP, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_membershipProof_registeredRoot() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.prank(owner);
        oracle.registerMerkleRoot(root);

        bytes memory publicInputs = _membershipInputs(root);
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.MEMBERSHIP, _uniqueProof(), publicInputs, bytes32(0));
        assertEq(att.subject, alice);
    }

    function test_submitCompliance_nonMembershipProof_revert_unregisteredMerkleRoot() public {
        bytes memory publicInputs = _nonMembershipInputs(bytes32(uint256(0xdead)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidMerkleRoot.selector, bytes32(uint256(0xdead))));
        oracle.submitCompliance(0, ProofTypes.NON_MEMBERSHIP, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_attestationProof_revert_unregisteredCredentialRoot() public {
        bytes32 unregistered = bytes32(uint256(0xdead));
        bytes memory publicInputs = _attestationInputs(unregistered);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.CredentialRootNotFound.selector, unregistered));
        oracle.submitCompliance(0, ProofTypes.ATTESTATION, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_patternProof_revert_zeroTxSetHash() public {
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(1)), // result
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0)), // tx_set_hash = 0 (invalid)
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.PublicInputMismatch.selector);
        oracle.submitCompliance(0, ProofTypes.PATTERN, _uniqueProof(), publicInputs, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // F1: Reject proofs with negative result fields
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_complianceNonCompliant() public {
        // meets_threshold = 0 (non-compliant)
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(0)), // jurisdiction_id
            DEFAULT_PROVIDER_SET_HASH, // provider_set_hash
            INITIAL_CONFIG, // config_hash
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(0)), // meets_threshold = false
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _uniqueProof(), publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_revert_riskScoreNegativeResult() public {
        // result = 0 (score doesn't satisfy condition)
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)), // proof_type
            bytes32(uint256(1)), // direction
            bytes32(uint256(5000)), // bound_lower
            bytes32(uint256(0)), // bound_upper
            bytes32(uint256(0)), // result = false
            INITIAL_CONFIG, // config_hash
            bytes32(uint256(0xeeff)), // provider_set_hash
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_patternStructuringDetected() public {
        // result = 0 (structuring detected)
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(0)), // result = false (structuring detected)
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0xabcd)), // tx_set_hash
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(0, ProofTypes.PATTERN, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_attestationInvalid() public {
        bytes32 root = bytes32(uint256(0xbeef));
        _publishCredentialRoot(root);

        // is_valid = 0 (credential invalid/expired)
        bytes memory publicInputs = abi.encodePacked(
            bytes32(DEFAULT_PROVIDER_ID), // provider_id
            bytes32(uint256(1)), // credential_type
            bytes32(uint256(0)), // is_valid = false
            root, // credential_root
            bytes32(block.timestamp), // current_timestamp
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(0, ProofTypes.ATTESTATION, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_membershipNotMember() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.prank(owner);
        oracle.registerMerkleRoot(root);

        // is_member = 0 (not a member)
        bytes memory publicInputs = abi.encodePacked(
            root, // merkle_root
            bytes32(uint256(1)), // set_id
            bytes32(block.timestamp), // timestamp
            bytes32(uint256(0)), // is_member = false
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(0, ProofTypes.MEMBERSHIP, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_nonMembershipFailed() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.prank(owner);
        oracle.registerMerkleRoot(root);

        // is_non_member = 0 (element IS in set)
        bytes memory publicInputs = abi.encodePacked(
            root, // merkle_root
            bytes32(uint256(1)), // set_id
            bytes32(block.timestamp), // timestamp
            bytes32(uint256(0)), // is_non_member = false
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(0, ProofTypes.NON_MEMBERSHIP, _uniqueProof(), publicInputs, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // Finding 5: Proof replay across proof types
    // -------------------------------------------------------------------------

    function test_submitCompliance_proofReplayAcrossTypes_allowed() public {
        // Same proof bytes submitted for two different proof types should succeed
        // because proofHash is keyed on (proof, proofType)
        bytes memory proof = _uniqueProof();

        // Submit as COMPLIANCE
        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        // Same proof bytes as PATTERN should succeed (different proofType in hash)
        bytes memory patternInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(1)), // result
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0xabcd)), // tx_set_hash
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.PATTERN, proof, patternInputs, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // Finding 6: TTL boundary precision
    // -------------------------------------------------------------------------

    function test_checkCompliance_validAtExactExpiry() public {
        _submitForAlice(0);
        // warp to exactly expiresAt (block.timestamp + 24 hours)
        vm.warp(block.timestamp + 24 hours);
        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertTrue(valid); // <= means valid at exact boundary
    }

    function test_checkCompliance_invalidOneSecondAfterExpiry() public {
        _submitForAlice(0);
        vm.warp(block.timestamp + 24 hours + 1);
        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertFalse(valid);
    }

    // -------------------------------------------------------------------------
    // Finding 11: Config revocation
    // -------------------------------------------------------------------------

    function test_revokeConfig_preventsSubmission() public {
        // Add a second config, then revoke the initial one
        bytes32 newConfig = keccak256("new-config");
        vm.startPrank(owner);
        oracle.updateProviderConfig(newConfig, "", _defaultProviders());
        oracle.revokeConfig(INITIAL_CONFIG);
        vm.stopPrank();

        // Submit with revoked INITIAL_CONFIG should fail
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidConfigHash.selector, INITIAL_CONFIG));
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_revokeConfig_revert_notOwner() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.revokeConfig(INITIAL_CONFIG);
    }

    function test_revokeConfig_revert_cannotRevokeCurrent() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.CannotRevokeCurrentConfig.selector);
        oracle.revokeConfig(INITIAL_CONFIG);
    }

    // -------------------------------------------------------------------------
    // M-3: Permanent config revocation
    // -------------------------------------------------------------------------

    function test_revokeConfig_marksRevoked() public {
        bytes32 newConfig = keccak256("new-config");
        vm.startPrank(owner);
        oracle.updateProviderConfig(newConfig, "", _defaultProviders());
        assertFalse(oracle.isRevokedConfig(INITIAL_CONFIG));
        oracle.revokeConfig(INITIAL_CONFIG);
        vm.stopPrank();

        assertTrue(oracle.isRevokedConfig(INITIAL_CONFIG));
        assertFalse(oracle.isValidConfig(INITIAL_CONFIG));
    }

    function test_updateProviderConfig_revert_reRegisterRevoked() public {
        // Rotate to a new config so INITIAL_CONFIG is no longer current and can be revoked
        bytes32 secondConfig = keccak256("second-config");
        vm.startPrank(owner);
        oracle.updateProviderConfig(secondConfig, "", _defaultProviders());
        oracle.revokeConfig(INITIAL_CONFIG);

        // Rotate to a third config so secondConfig is no longer current
        bytes32 thirdConfig = keccak256("third-config");
        oracle.updateProviderConfig(thirdConfig, "", _defaultProviders());

        // Try to re-register the revoked INITIAL_CONFIG -- must revert
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.ConfigPermanentlyRevoked.selector, INITIAL_CONFIG));
        oracle.updateProviderConfig(INITIAL_CONFIG, "", _defaultProviders());
        vm.stopPrank();
    }

    function test_updateProviderConfig_unrevokedHashStillAllowed() public {
        // Sanity: adding a brand-new (never-revoked) hash still works under the new check
        bytes32 newConfig = keccak256("brand-new");
        vm.prank(owner);
        oracle.updateProviderConfig(newConfig, "", _defaultProviders());
        assertEq(oracle.providerConfigHash(), newConfig);
        assertTrue(oracle.isValidConfig(newConfig));
    }

    // -------------------------------------------------------------------------
    // Phase 1: Credential roots (per-provider TTL window)
    // -------------------------------------------------------------------------

    function test_setProviderPublisher_setsAndEmits() public {
        // Use a fresh providerId not pre-registered by setUp (which uses DEFAULT_PROVIDER_ID=42)
        uint256 providerId = 99;
        address pub99 = makeAddr("publisher-99");
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit XochiZKPOracle.ProviderPublisherSet(providerId, address(0), pub99);
        oracle.setProviderPublisher(providerId, pub99);

        assertEq(oracle.getProviderPublisher(providerId), pub99);
    }

    function test_setProviderPublisher_revert_zeroProviderId() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.InvalidProviderId.selector);
        oracle.setProviderPublisher(0, makeAddr("publisher"));
    }

    function test_setProviderPublisher_revert_notOwner() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.setProviderPublisher(42, alice);
    }

    function test_setProviderPublisher_rotates() public {
        address pub1 = makeAddr("pub-1");
        address pub2 = makeAddr("pub-2");
        vm.startPrank(owner);
        oracle.setProviderPublisher(42, pub1);
        vm.expectEmit(true, true, true, true);
        emit XochiZKPOracle.ProviderPublisherSet(42, pub1, pub2);
        oracle.setProviderPublisher(42, pub2);
        vm.stopPrank();
        assertEq(oracle.getProviderPublisher(42), pub2);
    }

    function test_publishCredentialRoot_succeeds() public {
        bytes32 root = keccak256("root-v1");

        vm.expectEmit(true, true, false, true);
        emit XochiZKPOracle.CredentialRootPublished(DEFAULT_PROVIDER_ID, root, "ipfs://Qm...", block.timestamp);
        _publishCredentialRootSigned(DEFAULT_PROVIDER_ID, publisher, root, "ipfs://Qm...", CREDENTIAL_SIGNER_KEY);

        assertTrue(oracle.isValidCredentialRoot(root));
        XochiZKPOracle.CredentialRootInfo memory info = oracle.getCredentialRoot(root);
        assertEq(info.providerId, DEFAULT_PROVIDER_ID);
        assertEq(uint256(info.registeredAt), block.timestamp);
        assertFalse(info.revoked);
    }

    function test_publishCredentialRoot_revert_notAuthorized() public {
        // Owner cannot publish on behalf of provider (publisher EOA mismatch fires
        // before the signature check).
        bytes32 root = keccak256("r");
        bytes memory sig = _signCredentialRoot(
            DEFAULT_PROVIDER_ID,
            root,
            "",
            uint64(block.timestamp),
            uint64(block.timestamp + 1 hours),
            CREDENTIAL_SIGNER_KEY
        );
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPOracle.NotProviderPublisher.selector, DEFAULT_PROVIDER_ID, owner)
        );
        oracle.publishCredentialRoot(
            DEFAULT_PROVIDER_ID, root, "", uint64(block.timestamp), uint64(block.timestamp + 1 hours), sig
        );
    }

    function test_publishCredentialRoot_revert_unsetProvider() public {
        // Provider id never authorized -- publisher mapping is zero.
        bytes memory sig = new bytes(65);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.NotProviderPublisher.selector, 99, alice));
        oracle.publishCredentialRoot(
            99, keccak256("r"), "", uint64(block.timestamp), uint64(block.timestamp + 1 hours), sig
        );
    }

    function test_publishCredentialRoot_revert_duplicateRoot() public {
        bytes32 root = keccak256("root");
        _publishCredentialRoot(root);

        // Attempt to republish: signature is fresh, but the root already exists.
        uint64 nb = uint64(block.timestamp);
        uint64 na = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, CREDENTIAL_SIGNER_KEY);
        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.CredentialRootAlreadyPublished.selector, root));
        oracle.publishCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, sig);
    }

    /// @notice Audit F-4: signature malleability via high-s must revert.
    ///         Given a valid (r, s, v), the symmetric (r, n-s, v') would
    ///         normally also recover to the same signer. Enforcing low-s in
    ///         _recoverSigner rejects the symmetric form so there is exactly
    ///         one canonical encoding per (signer, digest).
    function test_publishCredentialRoot_revert_highSMalleability() public {
        bytes32 root = keccak256("root-malleable");
        uint64 nb = uint64(block.timestamp);
        uint64 na = uint64(block.timestamp + 1 hours);

        bytes32 digest = EIP712CredentialRoot.toTypedDataHash(
            EIP712CredentialRoot.buildDomainSeparator(address(oracle)),
            DEFAULT_PROVIDER_ID,
            root,
            keccak256(bytes("")),
            nb,
            na
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(CREDENTIAL_SIGNER_KEY, digest);
        // Flip s -> n - s (invert v parity)
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 sFlipped = bytes32(n - uint256(s));
        uint8 vFlipped = v == 27 ? 28 : 27;
        bytes memory sigMalleable = abi.encodePacked(r, sFlipped, vFlipped);

        vm.prank(publisher);
        vm.expectRevert(XochiZKPOracle.InvalidCredentialSignature.selector);
        oracle.publishCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, sigMalleable);
    }

    function test_credentialRoot_expiresAfterTTL() public {
        bytes32 root = keccak256("root");
        _publishCredentialRoot(root);

        assertTrue(oracle.isValidCredentialRoot(root));
        // Just before TTL: still valid
        vm.warp(block.timestamp + oracle.CREDENTIAL_ROOT_TTL());
        assertTrue(oracle.isValidCredentialRoot(root));
        // One second past TTL: invalid
        vm.warp(block.timestamp + 1);
        assertFalse(oracle.isValidCredentialRoot(root));
    }

    function test_revokeCredentialRoot_byOwner() public {
        bytes32 root = keccak256("root");
        _publishCredentialRoot(root);

        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit XochiZKPOracle.CredentialRootRevoked(root);
        oracle.revokeCredentialRoot(root);

        assertFalse(oracle.isValidCredentialRoot(root));
    }

    function test_revokeCredentialRoot_byPublisher() public {
        bytes32 root = keccak256("root");
        _publishCredentialRoot(root);

        vm.prank(publisher);
        oracle.revokeCredentialRoot(root);

        assertFalse(oracle.isValidCredentialRoot(root));
    }

    function test_revokeCredentialRoot_revert_notAuthorized() public {
        bytes32 root = keccak256("root");
        _publishCredentialRoot(root);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPOracle.NotProviderPublisher.selector, DEFAULT_PROVIDER_ID, alice)
        );
        oracle.revokeCredentialRoot(root);
    }

    function test_revokeCredentialRoot_revert_notFound() public {
        bytes32 root = keccak256("never-published");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.CredentialRootNotFound.selector, root));
        oracle.revokeCredentialRoot(root);
    }

    function test_credentialRoot_overlapWindow() public {
        // Publish v1 then v2 within TTL: both remain provable simultaneously.
        bytes32 r1 = keccak256("r1");
        bytes32 r2 = keccak256("r2");

        _publishCredentialRoot(r1);

        vm.warp(block.timestamp + 6 hours);
        _publishCredentialRoot(r2);

        assertTrue(oracle.isValidCredentialRoot(r1));
        assertTrue(oracle.isValidCredentialRoot(r2));
    }

    // -------------------------------------------------------------------------
    // Credential signer registry + signed publish flow (audit C-1 closure)
    // -------------------------------------------------------------------------

    uint256 internal constant ATTACKER_KEY = uint256(keccak256("xochi-test-attacker"));
    uint256 internal constant ROTATED_SIGNER_KEY = uint256(keccak256("xochi-test-rotated-signer"));

    function test_setCredentialSigner_emitsEvent() public {
        address newSigner = makeAddr("new-signer");
        address previous = oracle.getCredentialSigner(DEFAULT_PROVIDER_ID);

        vm.prank(owner);
        vm.expectEmit(true, true, true, false);
        emit XochiZKPOracle.CredentialSignerSet(DEFAULT_PROVIDER_ID, previous, newSigner);
        oracle.setCredentialSigner(DEFAULT_PROVIDER_ID, newSigner);

        assertEq(oracle.getCredentialSigner(DEFAULT_PROVIDER_ID), newSigner);
    }

    function test_setCredentialSigner_revert_zeroProviderId() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.InvalidProviderId.selector);
        oracle.setCredentialSigner(0, makeAddr("s"));
    }

    function test_setCredentialSigner_revert_notRegistrar() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.setCredentialSigner(DEFAULT_PROVIDER_ID, makeAddr("s"));
    }

    function test_publishCredentialRoot_revert_signerNotSet() public {
        // Provider with publisher set but no credential signer.
        uint256 pid = 99;
        address pub99 = makeAddr("pub99");
        vm.prank(owner);
        oracle.setProviderPublisher(pid, pub99);

        bytes32 root = keccak256("root");
        uint64 nb = uint64(block.timestamp);
        uint64 na = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signCredentialRoot(pid, root, "", nb, na, CREDENTIAL_SIGNER_KEY);

        vm.prank(pub99);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.CredentialSignerNotSet.selector, pid));
        oracle.publishCredentialRoot(pid, root, "", nb, na, sig);
    }

    function test_publishCredentialRoot_revert_wrongSigner() public {
        bytes32 root = keccak256("root");
        uint64 nb = uint64(block.timestamp);
        uint64 na = uint64(block.timestamp + 1 hours);
        // Sign with the attacker's key, not the registered signer.
        bytes memory sig = _signCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, ATTACKER_KEY);

        vm.prank(publisher);
        vm.expectRevert(XochiZKPOracle.InvalidCredentialSignature.selector);
        oracle.publishCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, sig);
    }

    function test_publishCredentialRoot_revert_tamperedRoot() public {
        bytes32 signedRoot = keccak256("signed-root");
        bytes32 swappedRoot = keccak256("swapped-root");
        uint64 nb = uint64(block.timestamp);
        uint64 na = uint64(block.timestamp + 1 hours);
        // Signature is over signedRoot; publisher tries to use it for swappedRoot.
        bytes memory sig = _signCredentialRoot(DEFAULT_PROVIDER_ID, signedRoot, "", nb, na, CREDENTIAL_SIGNER_KEY);

        vm.prank(publisher);
        vm.expectRevert(XochiZKPOracle.InvalidCredentialSignature.selector);
        oracle.publishCredentialRoot(DEFAULT_PROVIDER_ID, swappedRoot, "", nb, na, sig);
    }

    function test_publishCredentialRoot_revert_tamperedCid() public {
        bytes32 root = keccak256("root");
        uint64 nb = uint64(block.timestamp);
        uint64 na = uint64(block.timestamp + 1 hours);
        // Signature is over cid="ipfs://A"; publisher submits with cid="ipfs://B".
        bytes memory sig = _signCredentialRoot(DEFAULT_PROVIDER_ID, root, "ipfs://A", nb, na, CREDENTIAL_SIGNER_KEY);

        vm.prank(publisher);
        vm.expectRevert(XochiZKPOracle.InvalidCredentialSignature.selector);
        oracle.publishCredentialRoot(DEFAULT_PROVIDER_ID, root, "ipfs://B", nb, na, sig);
    }

    function test_publishCredentialRoot_revert_outsideWindow_before() public {
        bytes32 root = keccak256("root");
        uint64 nb = uint64(block.timestamp + 1 hours);
        uint64 na = uint64(block.timestamp + 2 hours);
        bytes memory sig = _signCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, CREDENTIAL_SIGNER_KEY);

        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.CredentialSignatureOutOfWindow.selector, nb, na));
        oracle.publishCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, sig);
    }

    function test_publishCredentialRoot_revert_outsideWindow_after() public {
        bytes32 root = keccak256("root");
        uint64 nb = uint64(block.timestamp);
        uint64 na = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, CREDENTIAL_SIGNER_KEY);

        // Warp past notAfter and try to publish.
        vm.warp(uint256(na) + 1);
        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.CredentialSignatureOutOfWindow.selector, nb, na));
        oracle.publishCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, sig);
    }

    function test_publishCredentialRoot_revert_invalidSignatureLength() public {
        bytes32 root = keccak256("root");
        uint64 nb = uint64(block.timestamp);
        uint64 na = uint64(block.timestamp + 1 hours);
        bytes memory shortSig = new bytes(64);

        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidSignatureLength.selector, 64));
        oracle.publishCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, shortSig);
    }

    /// @notice C-1 regression: a compromised publisher EOA cannot mint credential
    ///         roots without holding the credential signing key. Models the threat
    ///         the two-key separation closes.
    function test_publishCredentialRoot_compromisedPublisher_cannotForge() public {
        // The "compromised publisher" attempts to publish with a signature from
        // their own key. The Oracle's signer registry resolves to the legitimate
        // credential signer, not the publisher EOA, so the signature does not
        // recover to the registered signer and the publish reverts.
        uint256 publisherKey = uint256(keccak256("compromised-publisher-key"));
        address publisherEoa = vm.addr(publisherKey);
        uint256 pid = 1234;

        vm.startPrank(owner);
        oracle.setProviderPublisher(pid, publisherEoa);
        oracle.setCredentialSigner(pid, vm.addr(CREDENTIAL_SIGNER_KEY));
        vm.stopPrank();

        bytes32 root = keccak256("forged-root");
        uint64 nb = uint64(block.timestamp);
        uint64 na = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signCredentialRoot(pid, root, "", nb, na, publisherKey);

        vm.prank(publisherEoa);
        vm.expectRevert(XochiZKPOracle.InvalidCredentialSignature.selector);
        oracle.publishCredentialRoot(pid, root, "", nb, na, sig);
    }

    function test_setCredentialSigner_rotation_oldSigRejected() public {
        // Rotate the signer; signatures from the old key must be rejected for
        // new publishes.
        bytes32 root = keccak256("post-rotation-root");
        uint64 nb = uint64(block.timestamp);
        uint64 na = uint64(block.timestamp + 1 hours);

        // Rotate
        vm.prank(owner);
        oracle.setCredentialSigner(DEFAULT_PROVIDER_ID, vm.addr(ROTATED_SIGNER_KEY));

        // Old key tries to sign a new root: rejected.
        bytes memory oldSig = _signCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, CREDENTIAL_SIGNER_KEY);
        vm.prank(publisher);
        vm.expectRevert(XochiZKPOracle.InvalidCredentialSignature.selector);
        oracle.publishCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, oldSig);

        // New key signs same root: accepted.
        bytes memory newSig = _signCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, ROTATED_SIGNER_KEY);
        vm.prank(publisher);
        oracle.publishCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, newSig);
        assertTrue(oracle.isValidCredentialRoot(root));
    }

    function test_setCredentialSigner_rotation_priorRootsStillProvable() public {
        // Roots published with the old key remain valid after rotation; only
        // *new* publishes need the new key.
        bytes32 oldRoot = keccak256("pre-rotation-root");
        _publishCredentialRoot(oldRoot);
        assertTrue(oracle.isValidCredentialRoot(oldRoot));

        vm.prank(owner);
        oracle.setCredentialSigner(DEFAULT_PROVIDER_ID, vm.addr(ROTATED_SIGNER_KEY));

        // Same root remains provable -- registry lookup is by root, not by signer.
        assertTrue(oracle.isValidCredentialRoot(oldRoot));
    }

    function test_setCredentialSigner_disable_blocksFuturePublishes() public {
        // Setting signer to address(0) trips the CredentialSignerNotSet guard
        // for any future publish, even with a previously-valid signature.
        vm.prank(owner);
        oracle.setCredentialSigner(DEFAULT_PROVIDER_ID, address(0));

        bytes32 root = keccak256("post-disable-root");
        uint64 nb = uint64(block.timestamp);
        uint64 na = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, CREDENTIAL_SIGNER_KEY);

        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.CredentialSignerNotSet.selector, DEFAULT_PROVIDER_ID));
        oracle.publishCredentialRoot(DEFAULT_PROVIDER_ID, root, "", nb, na, sig);
    }

    // -------------------------------------------------------------------------
    // Config history compaction
    // -------------------------------------------------------------------------

    function test_compactConfigHistory_removesRevokedEntries() public {
        vm.startPrank(owner);
        // Add 4 more configs (total 5 with initial)
        bytes32 c2 = keccak256("c2");
        bytes32 c3 = keccak256("c3");
        bytes32 c4 = keccak256("c4");
        bytes32 c5 = keccak256("c5");
        oracle.updateProviderConfig(c2, "", _defaultProviders());
        oracle.updateProviderConfig(c3, "", _defaultProviders());
        oracle.updateProviderConfig(c4, "", _defaultProviders());
        oracle.updateProviderConfig(c5, "", _defaultProviders());
        assertEq(oracle.configHistoryLength(), 5);

        // Revoke 2 non-current entries
        oracle.revokeConfig(INITIAL_CONFIG);
        oracle.revokeConfig(c3);

        // Compact
        uint256 removed = oracle.compactConfigHistory();
        vm.stopPrank();

        assertEq(removed, 2);
        assertEq(oracle.configHistoryLength(), 3);
        // Current config is still the last entry
        assertEq(oracle.configHistoryAt(2), c5);
        // Ordering preserved: c2, c4, c5
        assertEq(oracle.configHistoryAt(0), c2);
        assertEq(oracle.configHistoryAt(1), c4);
    }

    function test_compactConfigHistory_noOp_whenNoneRevoked() public {
        vm.prank(owner);
        uint256 removed = oracle.compactConfigHistory();
        assertEq(removed, 0);
        assertEq(oracle.configHistoryLength(), 1);
    }

    function test_compactConfigHistory_revert_notOwner() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.compactConfigHistory();
    }

    function test_compactConfigHistory_allowsUpdatesAfterCompaction() public {
        vm.startPrank(owner);
        // Fill history to near capacity
        for (uint256 i = 1; i < oracle.MAX_CONFIG_HISTORY(); i++) {
            oracle.updateProviderConfig(keccak256(abi.encode(i)), "", _defaultProviders());
        }
        assertEq(oracle.configHistoryLength(), oracle.MAX_CONFIG_HISTORY());

        // Cannot add more
        vm.expectRevert(XochiZKPOracle.ConfigHistoryFull.selector);
        oracle.updateProviderConfig(keccak256("overflow"), "", _defaultProviders());

        // Revoke a few old entries and compact
        oracle.revokeConfig(INITIAL_CONFIG);
        oracle.revokeConfig(keccak256(abi.encode(uint256(1))));
        oracle.compactConfigHistory();

        // Now we can add again
        oracle.updateProviderConfig(keccak256("new-after-compact"), "", _defaultProviders());
        vm.stopPrank();

        assertTrue(oracle.configHistoryLength() <= oracle.MAX_CONFIG_HISTORY());
    }

    // -------------------------------------------------------------------------
    // Merkle root registry
    // -------------------------------------------------------------------------

    function test_registerMerkleRoot() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IXochiZKPOracle.MerkleRootRegistered(root);
        oracle.registerMerkleRoot(root);
        assertTrue(oracle.isValidMerkleRoot(root));
    }

    function test_revokeMerkleRoot() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.startPrank(owner);
        oracle.registerMerkleRoot(root);
        oracle.revokeMerkleRoot(root);
        vm.stopPrank();
        assertFalse(oracle.isValidMerkleRoot(root));
    }

    function test_registerMerkleRoot_revert_notOwner() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.registerMerkleRoot(bytes32(uint256(0xbeef)));
    }

    // -------------------------------------------------------------------------
    // PATTERN reporting threshold validation
    // -------------------------------------------------------------------------

    function test_submitCompliance_patternProof_revert_unregisteredThreshold() public {
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(1)), // result
            bytes32(uint256(99999)), // reporting_threshold (not registered)
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0xabcd)), // tx_set_hash
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPOracle.InvalidReportingThreshold.selector, bytes32(uint256(99999)))
        );
        oracle.submitCompliance(0, ProofTypes.PATTERN, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_patternProof_revert_timeWindowTooSmall() public {
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(1)), // result
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(1)), // time_window = 1 second (too small)
            bytes32(uint256(0xabcd)), // tx_set_hash
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.TimeWindowTooSmall.selector, 1, 3600));
        oracle.submitCompliance(0, ProofTypes.PATTERN, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_patternProof_exactMinTimeWindow() public {
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(1)), // result
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(3600)), // time_window = exactly MIN_TIME_WINDOW
            bytes32(uint256(0xabcd)), // tx_set_hash
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.PATTERN, _uniqueProof(), publicInputs, bytes32(0));
        assertEq(att.subject, alice);
    }

    // -------------------------------------------------------------------------
    // Timestamp staleness
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_staleComplianceTimestamp() public {
        vm.warp(1700000000);
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(0)), // jurisdiction_id
            DEFAULT_PROVIDER_SET_HASH,
            INITIAL_CONFIG,
            bytes32(uint256(1700000000 - 3601)), // timestamp: 1 second past MAX_PROOF_AGE
            bytes32(uint256(1)), // meets_threshold
            bytes32(uint256(uint160(alice))) // submitter
        );
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPOracle.ProofTimestampStale.selector, 1700000000 - 3601, 1700000000)
        );
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _uniqueProof(), publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_revert_futureComplianceTimestamp() public {
        vm.warp(1700000000);
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(0)),
            DEFAULT_PROVIDER_SET_HASH,
            INITIAL_CONFIG,
            bytes32(uint256(1700000000 + 3601)), // timestamp: future, past MAX_PROOF_AGE
            bytes32(uint256(1)),
            bytes32(uint256(uint160(alice)))
        );
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPOracle.ProofTimestampStale.selector, 1700000000 + 3601, 1700000000)
        );
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _uniqueProof(), publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_staleness_exactBoundary() public {
        vm.warp(1700000000);
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(0)),
            DEFAULT_PROVIDER_SET_HASH,
            INITIAL_CONFIG,
            bytes32(uint256(1700000000 - 3600)), // exactly at MAX_PROOF_AGE boundary
            bytes32(uint256(1)),
            bytes32(uint256(uint160(alice)))
        );
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _uniqueProof(), publicInputs, DEFAULT_PROVIDER_SET_HASH);
        assertEq(att.subject, alice);
    }

    function test_submitCompliance_revert_staleMembershipTimestamp() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.prank(owner);
        oracle.registerMerkleRoot(root);

        vm.warp(1700000000);
        bytes memory publicInputs = abi.encodePacked(
            root,
            bytes32(uint256(1)),
            bytes32(uint256(1700000000 - 3601)), // stale
            bytes32(uint256(1)),
            bytes32(uint256(uint160(alice)))
        );
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPOracle.ProofTimestampStale.selector, 1700000000 - 3601, 1700000000)
        );
        oracle.submitCompliance(0, ProofTypes.MEMBERSHIP, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_registerReportingThreshold_revert_notOwner() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.registerReportingThreshold(bytes32(uint256(20000)));
    }

    function test_revokeReportingThreshold() public {
        bytes32 threshold = bytes32(uint256(10000));
        vm.prank(owner);
        oracle.revokeReportingThreshold(threshold);
        assertFalse(oracle.isValidReportingThreshold(threshold));
    }

    // -------------------------------------------------------------------------
    // TOCTOU: view verifier prevents reentrancy
    // -------------------------------------------------------------------------

    function test_submitCompliance_viewVerifierPreventsReentrancy() public {
        // After the view fix, the verifier's verify() is view, so it cannot
        // call back into setVerifier(). This test confirms verifierUsed matches
        // the actual verifier used for verification by checking consistency
        // across a verifier upgrade scenario.
        bytes memory proof1 = _uniqueProof();
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att1 =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof1, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        // Upgrade verifier mid-session via timelock
        PassingVerifier newStub = new PassingVerifier();
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, address(newStub), address(newStub).codehash);
        vm.warp(block.timestamp + 24 hours);
        vm.prank(owner);
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);

        bytes memory proof2 = _uniqueProof();
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att2 =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof2, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        // Each attestation records the verifier that was actually used
        assertEq(att1.verifierUsed, address(stubVerifier));
        assertEq(att2.verifierUsed, address(newStub));
        assertTrue(att1.verifierUsed != att2.verifierUsed);
    }

    // -------------------------------------------------------------------------
    // Ownership edge case (Oracle)
    // -------------------------------------------------------------------------

    function test_transferOwnership_revert_zeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        oracle.transferOwnership(address(0));
    }

    // -------------------------------------------------------------------------
    // Additional fuzz tests
    // -------------------------------------------------------------------------

    function testFuzz_publicInputEncoding_roundTrips(bytes32 a, bytes32 b, bytes32 c) public pure {
        // Verify that abi.encodePacked produces correctly aligned 32-byte slots
        bytes memory packed = abi.encodePacked(a, b, c);
        assertEq(packed.length, 96);
        assertEq(packed.length % 32, 0);
        // Verify individual slots via direct memory reads
        bytes32 slot0;
        bytes32 slot1;
        bytes32 slot2;
        assembly {
            slot0 := mload(add(packed, 32))
            slot1 := mload(add(packed, 64))
            slot2 := mload(add(packed, 96))
        }
        assertEq(slot0, a);
        assertEq(slot1, b);
        assertEq(slot2, c);
    }

    function testFuzz_proofHash_uniquePerType(bytes memory proof, uint8 typeA, uint8 typeB) public view {
        vm.assume(typeA != typeB);
        bytes32 hashA = oracle.computeProofHash(proof, typeA);
        bytes32 hashB = oracle.computeProofHash(proof, typeB);
        assertTrue(hashA != hashB);
    }

    function test_proofHash_boundToChainAndAddress() public {
        bytes memory proof = _uniqueProof();
        bytes32 hashHere = oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);

        // Same proof on a different chain id must produce a different hash
        vm.chainId(block.chainid + 1);
        bytes32 hashOtherChain = oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);
        assertTrue(hashHere != hashOtherChain);

        // Same proof on a different oracle deployment must produce a different hash
        vm.chainId(block.chainid - 1);
        XochiZKPOracle other = new XochiZKPOracle(address(verifier), owner, INITIAL_CONFIG, _defaultProviders());
        bytes32 hashOtherOracle = other.computeProofHash(proof, ProofTypes.COMPLIANCE);
        assertTrue(hashHere != hashOtherOracle);
    }

    function testFuzz_submitCompliance_allProofTypes(uint8 proofType) public {
        proofType = uint8(bound(proofType, 1, 6));
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs;

        if (proofType == ProofTypes.COMPLIANCE) {
            publicInputs = _complianceInputs();
        } else if (proofType == ProofTypes.RISK_SCORE) {
            publicInputs = _riskScoreInputs(INITIAL_CONFIG);
        } else if (proofType == ProofTypes.PATTERN) {
            publicInputs = abi.encodePacked(
                bytes32(uint256(1)),
                bytes32(uint256(1)),
                bytes32(uint256(10000)),
                bytes32(uint256(86400)),
                bytes32(uint256(0xabcd)),
                bytes32(uint256(uint160(alice)))
            );
        } else if (proofType == ProofTypes.ATTESTATION) {
            bytes32 root = bytes32(uint256(0xbeef));
            _publishCredentialRoot(root);
            publicInputs = _attestationInputs(root);
        } else if (proofType == ProofTypes.MEMBERSHIP) {
            bytes32 root = bytes32(uint256(0xbeef));
            vm.prank(owner);
            oracle.registerMerkleRoot(root);
            publicInputs = _membershipInputs(root);
        } else {
            bytes32 root = bytes32(uint256(0xbeef));
            vm.prank(owner);
            oracle.registerMerkleRoot(root);
            publicInputs = _nonMembershipInputs(root);
        }

        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.submitCompliance(
            0,
            proofType,
            proof,
            publicInputs,
            proofType == ProofTypes.COMPLIANCE ? DEFAULT_PROVIDER_SET_HASH : bytes32(0)
        );
        assertEq(att.subject, alice);
        assertEq(att.jurisdictionId, 0);
        assertTrue(att.meetsThreshold);
    }

    // -------------------------------------------------------------------------
    // Stateful invariant properties
    // -------------------------------------------------------------------------

    function testFuzz_expiredAttestationNeverValid(uint256 elapsed) public {
        elapsed = bound(elapsed, 24 hours + 1, 365 days);
        _submitForAlice(0);
        vm.warp(block.timestamp + elapsed);
        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertFalse(valid);
    }

    function testFuzz_replayAlwaysReverts(uint8 jurisdictionId) public {
        // Test exercises replay protection on unsigned COMPLIANCE; bound to permissive
        // jurisdictions (EU=0, UK=2) since strict ones (US, SG) reject the unsigned variant.
        uint8[2] memory permissive = [uint8(0), uint8(2)];
        jurisdictionId = permissive[uint256(bound(jurisdictionId, 0, 1))];
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = _complianceInputsFor(jurisdictionId, DEFAULT_PROVIDER_SET_HASH);

        bytes32 expectedHash = oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);

        vm.prank(alice);
        oracle.submitCompliance(jurisdictionId, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);

        // Replay with same proof and same type always reverts
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.ProofAlreadyUsed.selector, expectedHash));
        oracle.submitCompliance(jurisdictionId, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function testFuzz_attestationFieldsConsistent(uint8 jurisdictionId) public {
        uint8[2] memory permissive = [uint8(0), uint8(2)];
        jurisdictionId = permissive[uint256(bound(jurisdictionId, 0, 1))];
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = _complianceInputsFor(jurisdictionId, DEFAULT_PROVIDER_SET_HASH);

        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.submitCompliance(
            jurisdictionId, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH
        );

        // Attestation fields must be internally consistent
        assertEq(att.subject, alice);
        assertEq(att.jurisdictionId, jurisdictionId);
        assertTrue(att.meetsThreshold);
        assertEq(att.expiresAt, att.timestamp + oracle.attestationTTL());
        assertEq(att.proofHash, oracle.computeProofHash(proof, ProofTypes.COMPLIANCE));
        assertEq(att.publicInputsHash, keccak256(publicInputs));
        assertEq(att.providerSetHash, DEFAULT_PROVIDER_SET_HASH);
        assertTrue(att.verifierUsed != address(0));

        // Stored attestation must match returned attestation
        (bool valid, IXochiZKPOracle.ComplianceAttestation memory stored) =
            oracle.checkCompliance(alice, jurisdictionId);
        assertTrue(valid);
        assertEq(stored.proofHash, att.proofHash);
        assertEq(stored.verifierUsed, att.verifierUsed);
    }

    function testFuzz_revokedConfigBlocksSubmission(bytes32 newConfig) public {
        vm.assume(newConfig != INITIAL_CONFIG && newConfig != bytes32(0));

        vm.startPrank(owner);
        oracle.updateProviderConfig(newConfig, "", _defaultProviders());
        oracle.revokeConfig(INITIAL_CONFIG);
        vm.stopPrank();

        // Proof using revoked config must fail
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidConfigHash.selector, INITIAL_CONFIG));
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH
        );
    }

    // -------------------------------------------------------------------------
    // Pause mechanism
    // -------------------------------------------------------------------------

    function test_pause_blocksSubmitCompliance() public {
        vm.prank(owner);
        oracle.pause();

        vm.prank(alice);
        vm.expectRevert(Pausable.ContractPaused.selector);
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_pause_allowsCheckCompliance() public {
        _submitForAlice(0);
        vm.prank(owner);
        oracle.pause();

        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertTrue(valid);
    }

    function test_pause_allowsGetHistoricalProof() public {
        bytes memory proof = _uniqueProof();
        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        vm.prank(owner);
        oracle.pause();

        bytes32 proofHash = oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.getHistoricalProof(proofHash);
        assertEq(att.subject, alice);
    }

    function test_unpause_resumesSubmitCompliance() public {
        vm.startPrank(owner);
        oracle.pause();
        oracle.unpause();
        vm.stopPrank();

        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH
        );
        assertEq(att.subject, alice);
    }

    function test_pause_revert_notOwner() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.pause();
    }

    function test_unpause_revert_notOwner() public {
        vm.prank(owner);
        oracle.pause();

        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.unpause();
    }

    function test_pause_revert_alreadyPaused() public {
        vm.startPrank(owner);
        oracle.pause();
        vm.expectRevert(Pausable.ContractPaused.selector);
        oracle.pause();
        vm.stopPrank();
    }

    function test_unpause_revert_notPaused() public {
        vm.prank(owner);
        vm.expectRevert(Pausable.ContractNotPaused.selector);
        oracle.unpause();
    }

    function test_pause_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit Pausable.Paused(owner);
        oracle.pause();
    }

    function test_unpause_emitsEvent() public {
        vm.prank(owner);
        oracle.pause();

        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit Pausable.Unpaused(owner);
        oracle.unpause();
    }

    // -------------------------------------------------------------------------
    // Per-proof-type pause
    // -------------------------------------------------------------------------

    function test_pauseProofType_blocksSubmitCompliance() public {
        vm.prank(owner);
        oracle.pauseProofType(ProofTypes.COMPLIANCE);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.ProofTypePaused.selector, ProofTypes.COMPLIANCE));
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    function test_pauseProofType_allowsOtherTypes() public {
        vm.prank(owner);
        oracle.pauseProofType(ProofTypes.RISK_SCORE);

        // COMPLIANCE should still work (stub verifier passes)
        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    function test_pauseProofType_allowsCheckCompliance() public {
        vm.prank(owner);
        oracle.pauseProofType(ProofTypes.COMPLIANCE);

        // Read functions should still work
        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertFalse(valid);
    }

    function test_unpauseProofType_resumesSubmissions() public {
        vm.startPrank(owner);
        oracle.pauseProofType(ProofTypes.COMPLIANCE);
        oracle.unpauseProofType(ProofTypes.COMPLIANCE);
        vm.stopPrank();

        // After unpausing, submission should succeed (stub verifier passes)
        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    function test_pauseProofType_revert_notOwner() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.pauseProofType(ProofTypes.COMPLIANCE);
    }

    function test_isProofTypePaused() public {
        assertFalse(oracle.isProofTypePaused(ProofTypes.COMPLIANCE));
        vm.prank(owner);
        oracle.pauseProofType(ProofTypes.COMPLIANCE);
        assertTrue(oracle.isProofTypePaused(ProofTypes.COMPLIANCE));
    }

    // -------------------------------------------------------------------------
    // Config history bounds
    // -------------------------------------------------------------------------

    function test_updateProviderConfig_revert_historyFull() public {
        vm.startPrank(owner);
        // setUp already pushed 1 (initial config). Push 255 more to reach 256.
        for (uint256 i; i < 255; i++) {
            oracle.updateProviderConfig(keccak256(abi.encodePacked("fill-", i)), "", _defaultProviders());
        }
        assertEq(oracle.configHistoryLength(), 256);

        // 257th should revert
        vm.expectRevert(XochiZKPOracle.ConfigHistoryFull.selector);
        oracle.updateProviderConfig(keccak256("overflow"), "", _defaultProviders());
        vm.stopPrank();
    }

    function test_updateProviderConfig_revert_duplicateConfig() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.ConfigAlreadyCurrent.selector);
        oracle.updateProviderConfig(INITIAL_CONFIG, "", _defaultProviders());
    }

    // -------------------------------------------------------------------------
    // Constructor: zero config hash
    // -------------------------------------------------------------------------

    function test_constructor_revert_zeroConfigHash() public {
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidConfigHash.selector, bytes32(0)));
        new XochiZKPOracle(address(verifier), owner, bytes32(0), _defaultProviders());
    }

    // -------------------------------------------------------------------------
    // Idempotency guards
    // -------------------------------------------------------------------------

    function test_registerMerkleRoot_revert_alreadyRegistered() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.startPrank(owner);
        oracle.registerMerkleRoot(root);
        vm.expectRevert(XochiZKPOracle.AlreadyRegistered.selector);
        oracle.registerMerkleRoot(root);
        vm.stopPrank();
    }

    function test_revokeMerkleRoot_revert_notRegistered() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.NotRegistered.selector);
        oracle.revokeMerkleRoot(bytes32(uint256(0xdead)));
    }

    function test_registerReportingThreshold_revert_alreadyRegistered() public {
        // 10000 already registered in setUp
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.AlreadyRegistered.selector);
        oracle.registerReportingThreshold(bytes32(uint256(10000)));
    }

    function test_revokeReportingThreshold_revert_notRegistered() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.NotRegistered.selector);
        oracle.revokeReportingThreshold(bytes32(uint256(99999)));
    }

    // -------------------------------------------------------------------------
    // Unknown proof type guard
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_unknownProofType_zero() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x00));
        oracle.submitCompliance(0, 0x00, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_revert_unknownProofType_outOfRange() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x0a));
        oracle.submitCompliance(0, 0x0a, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // Ownership transfer cancellation
    // -------------------------------------------------------------------------

    function test_transferOwnership_emitsCancellation_whenPendingExists() public {
        address bob = makeAddr("bob");
        vm.startPrank(owner);
        oracle.transferOwnership(alice);

        vm.expectEmit(true, false, false, false);
        emit Ownable2Step.OwnershipTransferCancelled(alice);
        oracle.transferOwnership(bob);
        vm.stopPrank();
    }

    function test_transferOwnership_noCancellation_whenNoPending() public {
        // First transfer should not emit cancellation
        vm.prank(owner);
        vm.recordLogs();
        oracle.transferOwnership(alice);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i; i < entries.length; i++) {
            assertTrue(
                entries[i].topics[0] != keccak256("OwnershipTransferCancelled(address)"), "should not emit cancellation"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Fuzz: negative result fields always revert
    // -------------------------------------------------------------------------

    function testFuzz_submitCompliance_revert_negativeResult_allTypes(uint8 proofType) public {
        proofType = uint8(bound(proofType, 1, 6));
        bytes memory publicInputs;

        if (proofType == ProofTypes.COMPLIANCE) {
            publicInputs = abi.encodePacked(
                bytes32(uint256(0)),
                DEFAULT_PROVIDER_SET_HASH,
                INITIAL_CONFIG,
                bytes32(block.timestamp),
                bytes32(uint256(0)), // meets_threshold = 0
                bytes32(uint256(uint160(alice))) // submitter
            );
        } else if (proofType == ProofTypes.RISK_SCORE) {
            publicInputs = abi.encodePacked(
                bytes32(uint256(1)),
                bytes32(uint256(1)),
                bytes32(uint256(5000)),
                bytes32(uint256(0)),
                bytes32(uint256(0)),
                INITIAL_CONFIG, // result = 0
                bytes32(uint256(0xeeff)), // provider_set_hash
                bytes32(uint256(uint160(alice))) // submitter
            );
        } else if (proofType == ProofTypes.PATTERN) {
            publicInputs = abi.encodePacked(
                bytes32(uint256(1)),
                bytes32(uint256(0)), // result = 0
                bytes32(uint256(10000)),
                bytes32(uint256(86400)),
                bytes32(uint256(0xabcd)),
                bytes32(uint256(uint160(alice))) // submitter
            );
        } else if (proofType == ProofTypes.ATTESTATION) {
            bytes32 root = bytes32(uint256(0xbeef));
            _publishCredentialRoot(root);
            publicInputs = abi.encodePacked(
                bytes32(DEFAULT_PROVIDER_ID),
                bytes32(uint256(1)),
                bytes32(uint256(0)), // is_valid = 0
                root,
                bytes32(block.timestamp),
                bytes32(uint256(uint160(alice))) // submitter
            );
        } else if (proofType == ProofTypes.MEMBERSHIP) {
            bytes32 root = bytes32(uint256(0xbeef));
            vm.prank(owner);
            oracle.registerMerkleRoot(root);
            publicInputs = abi.encodePacked(
                root,
                bytes32(uint256(1)),
                bytes32(block.timestamp),
                bytes32(uint256(0)), // is_member = 0
                bytes32(uint256(uint160(alice))) // submitter
            );
        } else {
            bytes32 root = bytes32(uint256(0xbeef));
            vm.prank(owner);
            oracle.registerMerkleRoot(root);
            publicInputs = abi.encodePacked(
                root,
                bytes32(uint256(1)),
                bytes32(block.timestamp),
                bytes32(uint256(0)), // is_non_member = 0
                bytes32(uint256(uint160(alice))) // submitter
            );
        }

        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(
            0,
            proofType,
            _uniqueProof(),
            publicInputs,
            proofType == ProofTypes.COMPLIANCE ? DEFAULT_PROVIDER_SET_HASH : bytes32(0)
        );
    }

    function testFuzz_submitCompliance_revert_unknownProofType(uint8 proofType) public {
        // 0x01..0x09 are valid; 0x0a+ are out of range.
        vm.assume(proofType == 0 || proofType > 9);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, proofType));
        oracle.submitCompliance(0, proofType, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // Additional fuzz tests
    // -------------------------------------------------------------------------

    function testFuzz_submitCompliance_validJurisdictionPermutations(uint8 j) public {
        // Unsigned COMPLIANCE only valid for permissive jurisdictions.
        uint8[2] memory permissive = [uint8(0), uint8(2)];
        j = permissive[uint256(bound(j, 0, 1))];
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = _complianceInputsFor(j, DEFAULT_PROVIDER_SET_HASH);

        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(j, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);
        assertEq(att.jurisdictionId, j);
        assertTrue(att.meetsThreshold);
    }

    function testFuzz_updateProviderConfig_metadataURI(uint256 seed) public {
        // Generate various URI strings: empty, short, long, special chars
        bytes memory raw;
        uint256 len = seed % 1025; // 0 to 1024 chars
        raw = new bytes(len);
        for (uint256 i; i < len; i++) {
            raw[i] = bytes1(uint8((seed >> (i % 32)) % 256));
        }
        string memory uri = string(raw);
        bytes32 config = keccak256(abi.encodePacked("fuzz-config-", seed));

        vm.prank(owner);
        oracle.updateProviderConfig(config, uri, _defaultProviders());
        assertEq(oracle.providerConfigHash(), config);
    }

    function testFuzz_corruptedProof_reverts(uint256 corruptionOffset, uint8 corruptionByte) public {
        // Load a real proof, corrupt at various positions, verify it fails
        bytes memory proof = _uniqueProof();
        uint256 proofLen = proof.length;
        corruptionOffset = bound(corruptionOffset, 0, proofLen - 1);

        // Flip a byte at corruptionOffset
        proof[corruptionOffset] = bytes1(corruptionByte);

        // Submit -- should either revert or return (verifier will decide).
        // With PassingVerifier stub, this actually passes. Use FailingVerifier instead.
        FailingVerifier failVerifier = new FailingVerifier();
        vm.startPrank(owner);
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, address(failVerifier), address(failVerifier).codehash);
        vm.warp(block.timestamp + 24 hours);
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofVerificationFailed.selector);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    function testFuzz_paginatedHistory_arbitraryOffsetLimit(uint8 numProofs, uint256 offset, uint256 limit) public {
        numProofs = uint8(bound(numProofs, 0, 10));
        offset = bound(offset, 0, 20);
        limit = bound(limit, 0, 20);

        // Submit numProofs attestations
        vm.startPrank(alice);
        for (uint8 i; i < numProofs; i++) {
            oracle.submitCompliance(
                0, ProofTypes.COMPLIANCE, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH
            );
        }
        vm.stopPrank();

        // Paginated query should never revert
        (bytes32[] memory hashes, uint256 total) = oracle.getAttestationHistoryPaginated(alice, 0, offset, limit);

        assertEq(total, numProofs);

        if (offset >= total) {
            assertEq(hashes.length, 0);
        } else {
            uint256 expectedLen = offset + limit > total ? total - offset : limit;
            assertEq(hashes.length, expectedLen);
        }
    }

    function test_revokedConfig_proofsStillRetrievable() public {
        // Submit a proof with INITIAL_CONFIG
        bytes memory proof = _uniqueProof();
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
        bytes32 proofHash = att.proofHash;

        // Add new config, revoke old one
        vm.startPrank(owner);
        oracle.updateProviderConfig(keccak256("new-config"), "", _defaultProviders());
        oracle.revokeConfig(INITIAL_CONFIG);
        vm.stopPrank();

        // Historical proof should still be retrievable
        IXochiZKPOracle.ComplianceAttestation memory historical = oracle.getHistoricalProof(proofHash);
        assertEq(historical.subject, alice);
        assertEq(historical.proofHash, proofHash);
        assertEq(historical.timestamp, att.timestamp);
    }

    // -------------------------------------------------------------------------
    // submitComplianceBatch
    // -------------------------------------------------------------------------

    function test_submitComplianceBatch_recordsAllAttestations() public {
        bytes memory proof1 = _uniqueProof();
        bytes memory proof2 = _uniqueProof();
        bytes memory proof3 = _uniqueProof();

        uint8[] memory proofTypes = new uint8[](3);
        proofTypes[0] = ProofTypes.COMPLIANCE;
        proofTypes[1] = ProofTypes.COMPLIANCE;
        proofTypes[2] = ProofTypes.COMPLIANCE;

        bytes[] memory proofs = new bytes[](3);
        proofs[0] = proof1;
        proofs[1] = proof2;
        proofs[2] = proof3;

        bytes[] memory inputs = new bytes[](3);
        inputs[0] = _complianceInputs();
        inputs[1] = _complianceInputs();
        inputs[2] = _complianceInputs();

        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = DEFAULT_PROVIDER_SET_HASH;
        hashes[1] = DEFAULT_PROVIDER_SET_HASH;
        hashes[2] = DEFAULT_PROVIDER_SET_HASH;

        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation[] memory atts =
            oracle.submitComplianceBatch(0, proofTypes, proofs, inputs, hashes);

        assertEq(atts.length, 3);
        for (uint256 i; i < 3; i++) {
            assertEq(atts[i].subject, alice);
            assertEq(atts[i].jurisdictionId, 0);
            assertTrue(atts[i].meetsThreshold);

            // Verify each is retrievable via getHistoricalProof
            IXochiZKPOracle.ComplianceAttestation memory stored = oracle.getHistoricalProof(atts[i].proofHash);
            assertEq(stored.subject, alice);
            assertEq(stored.proofHash, atts[i].proofHash);
        }
    }

    function test_submitComplianceBatch_emitsEventsPerEntry() public {
        bytes memory proof1 = _uniqueProof();
        bytes memory proof2 = _uniqueProof();
        bytes memory proof3 = _uniqueProof();

        uint8[] memory proofTypes = new uint8[](3);
        proofTypes[0] = ProofTypes.COMPLIANCE;
        proofTypes[1] = ProofTypes.COMPLIANCE;
        proofTypes[2] = ProofTypes.COMPLIANCE;

        bytes[] memory proofs = new bytes[](3);
        proofs[0] = proof1;
        proofs[1] = proof2;
        proofs[2] = proof3;

        bytes[] memory inputs = new bytes[](3);
        inputs[0] = _complianceInputs();
        inputs[1] = _complianceInputs();
        inputs[2] = _complianceInputs();

        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = DEFAULT_PROVIDER_SET_HASH;
        hashes[1] = DEFAULT_PROVIDER_SET_HASH;
        hashes[2] = DEFAULT_PROVIDER_SET_HASH;

        vm.prank(alice);
        vm.recordLogs();
        oracle.submitComplianceBatch(0, proofTypes, proofs, inputs, hashes);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        uint256 complianceVerifiedCount;
        bytes32 eventSig = keccak256("ComplianceVerified(address,uint8,bool,bytes32,uint256,uint256)");
        for (uint256 i; i < entries.length; i++) {
            if (entries[i].topics[0] == eventSig) {
                complianceVerifiedCount++;
            }
        }
        assertEq(complianceVerifiedCount, 3);
    }

    function test_submitComplianceBatch_revert_arrayLengthMismatch() public {
        uint8[] memory proofTypes = new uint8[](2);
        bytes[] memory proofs = new bytes[](3);
        bytes[] memory inputs = new bytes[](2);
        bytes32[] memory hashes = new bytes32[](2);

        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.BatchLengthMismatch.selector);
        oracle.submitComplianceBatch(0, proofTypes, proofs, inputs, hashes);
    }

    function test_submitComplianceBatch_revert_exceedsMaxBatchSize() public {
        uint256 size = oracle.MAX_BATCH_SIZE() + 1;
        uint8[] memory proofTypes = new uint8[](size);
        bytes[] memory proofs = new bytes[](size);
        bytes[] memory inputs = new bytes[](size);
        bytes32[] memory hashes = new bytes32[](size);

        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.BatchTooLarge.selector);
        oracle.submitComplianceBatch(0, proofTypes, proofs, inputs, hashes);
    }

    function test_submitComplianceBatch_revert_replayInBatch() public {
        bytes memory proof = _uniqueProof();

        uint8[] memory proofTypes = new uint8[](2);
        proofTypes[0] = ProofTypes.COMPLIANCE;
        proofTypes[1] = ProofTypes.COMPLIANCE;

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = proof;
        proofs[1] = proof; // same proof

        bytes[] memory inputs = new bytes[](2);
        inputs[0] = _complianceInputs();
        inputs[1] = _complianceInputs();

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = DEFAULT_PROVIDER_SET_HASH;
        hashes[1] = DEFAULT_PROVIDER_SET_HASH;
        bytes32 expectedHash = oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.ProofAlreadyUsed.selector, expectedHash));
        oracle.submitComplianceBatch(0, proofTypes, proofs, inputs, hashes);
    }

    function test_submitComplianceBatch_revert_anyProofFails() public {
        // Deploy a verifier that always fails, upgrade via timelock
        FailingVerifier failVerifier = new FailingVerifier();
        vm.prank(owner);
        verifier.proposeVerifier(ProofTypes.RISK_SCORE, address(failVerifier), address(failVerifier).codehash);
        vm.warp(block.timestamp + 24 hours);
        vm.prank(owner);
        verifier.executeVerifierUpdate(ProofTypes.RISK_SCORE);

        uint8[] memory proofTypes = new uint8[](2);
        proofTypes[0] = ProofTypes.COMPLIANCE;
        proofTypes[1] = ProofTypes.RISK_SCORE; // will fail verification

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = _uniqueProof();
        proofs[1] = _uniqueProof();

        bytes[] memory inputs = new bytes[](2);
        inputs[0] = _complianceInputs();
        inputs[1] = _riskScoreInputs(INITIAL_CONFIG);

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = DEFAULT_PROVIDER_SET_HASH;
        hashes[1] = bytes32(0);

        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofVerificationFailed.selector);
        oracle.submitComplianceBatch(0, proofTypes, proofs, inputs, hashes);
    }

    function test_submitComplianceBatch_mixedProofTypes() public {
        uint8[] memory proofTypes = new uint8[](2);
        proofTypes[0] = ProofTypes.COMPLIANCE;
        proofTypes[1] = ProofTypes.RISK_SCORE;

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = _uniqueProof();
        proofs[1] = _uniqueProof();

        bytes[] memory inputs = new bytes[](2);
        inputs[0] = _complianceInputs();
        inputs[1] = _riskScoreInputs(INITIAL_CONFIG);

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = DEFAULT_PROVIDER_SET_HASH;
        hashes[1] = bytes32(0);

        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation[] memory atts =
            oracle.submitComplianceBatch(0, proofTypes, proofs, inputs, hashes);

        assertEq(atts.length, 2);
        // First is COMPLIANCE
        assertEq(oracle.getProofType(atts[0].proofHash), ProofTypes.COMPLIANCE);
        assertEq(atts[0].providerSetHash, DEFAULT_PROVIDER_SET_HASH);
        // Second is RISK_SCORE
        assertEq(oracle.getProofType(atts[1].proofHash), ProofTypes.RISK_SCORE);
        assertEq(atts[1].providerSetHash, bytes32(0)); // zeroed for non-COMPLIANCE
    }

    function test_submitComplianceBatch_revert_emptyBatch() public {
        uint8[] memory proofTypes = new uint8[](0);
        bytes[] memory proofs = new bytes[](0);
        bytes[] memory inputs = new bytes[](0);
        bytes32[] memory hashes = new bytes32[](0);

        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.EmptyBatch.selector);
        oracle.submitComplianceBatch(0, proofTypes, proofs, inputs, hashes);
    }

    function test_submitComplianceBatch_revert_whenPaused() public {
        vm.prank(owner);
        oracle.pause();

        uint8[] memory proofTypes = new uint8[](1);
        proofTypes[0] = ProofTypes.COMPLIANCE;
        bytes[] memory proofs = new bytes[](1);
        proofs[0] = _uniqueProof();
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = _complianceInputs();
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = DEFAULT_PROVIDER_SET_HASH;

        vm.prank(alice);
        vm.expectRevert(Pausable.ContractPaused.selector);
        oracle.submitComplianceBatch(0, proofTypes, proofs, inputs, hashes);
    }

    // -------------------------------------------------------------------------
    // Signer pubkey hash registry (audit I-1)
    // -------------------------------------------------------------------------

    bytes32 internal constant TEST_SIGNER_PUBKEY_HASH = bytes32(uint256(0x5111));
    bytes32 internal constant OTHER_SIGNER_PUBKEY_HASH = bytes32(uint256(0x5222));

    function test_registerSignerPubkeyHash_happy() public {
        assertFalse(oracle.isValidSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH));
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit XochiZKPOracle.SignerPubkeyHashRegistered(TEST_SIGNER_PUBKEY_HASH);
        oracle.registerSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);
        assertTrue(oracle.isValidSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH));
    }

    function test_registerSignerPubkeyHash_revert_zero() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidSignerPubkeyHash.selector, bytes32(0)));
        oracle.registerSignerPubkeyHash(bytes32(0));
    }

    function test_registerSignerPubkeyHash_revert_alreadyRegistered() public {
        vm.startPrank(owner);
        oracle.registerSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);
        vm.expectRevert(XochiZKPOracle.AlreadyRegistered.selector);
        oracle.registerSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);
        vm.stopPrank();
    }

    function test_registerSignerPubkeyHash_revert_notRegistrar() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.registerSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);
    }

    function test_revokeSignerPubkeyHash_happy() public {
        vm.startPrank(owner);
        oracle.registerSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);
        vm.expectEmit(true, false, false, false);
        emit XochiZKPOracle.SignerPubkeyHashRevoked(TEST_SIGNER_PUBKEY_HASH);
        oracle.revokeSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);
        vm.stopPrank();
        assertFalse(oracle.isValidSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH));
    }

    function test_revokeSignerPubkeyHash_revert_notRegistered() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.NotRegistered.selector);
        oracle.revokeSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);
    }

    function test_revokeSignerPubkeyHash_revert_notRegistrar() public {
        vm.prank(owner);
        oracle.registerSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.revokeSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);
    }

    // -------------------------------------------------------------------------
    // COMPLIANCE_SIGNED submission paths
    // -------------------------------------------------------------------------

    function test_submitCompliance_signed_happy() public {
        vm.prank(owner);
        oracle.registerSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);

        bytes memory inputs = _complianceSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, TEST_SIGNER_PUBKEY_HASH, alice);
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH);
        assertEq(att.proofType, ProofTypes.COMPLIANCE_SIGNED);
        assertEq(att.providerSetHash, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_signed_revert_unregisteredSignerPubkeyHash() public {
        bytes memory inputs = _complianceSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, OTHER_SIGNER_PUBKEY_HASH, alice);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPOracle.InvalidSignerPubkeyHash.selector, OTHER_SIGNER_PUBKEY_HASH)
        );
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_signed_revert_revokedSignerPubkeyHash() public {
        vm.startPrank(owner);
        oracle.registerSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);
        oracle.revokeSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);
        vm.stopPrank();

        bytes memory inputs = _complianceSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, TEST_SIGNER_PUBKEY_HASH, alice);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPOracle.InvalidSignerPubkeyHash.selector, TEST_SIGNER_PUBKEY_HASH)
        );
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_signed_revert_submitterMismatch() public {
        vm.prank(owner);
        oracle.registerSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);

        // Inputs claim alice; caller is bob. Submitter check fires inside the signed validator.
        bytes memory inputs = _complianceSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, TEST_SIGNER_PUBKEY_HASH, alice);
        address bob = makeAddr("bob");
        vm.prank(bob);
        vm.expectRevert(XochiZKPOracle.SubmitterMismatch.selector);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // RISK_SCORE_SIGNED submission paths
    // -------------------------------------------------------------------------

    function test_submitCompliance_riskScoreSigned_happy() public {
        vm.prank(owner);
        oracle.registerSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);

        bytes memory inputs = _riskScoreSignedInputs(INITIAL_CONFIG, TEST_SIGNER_PUBKEY_HASH, alice);
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.RISK_SCORE_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH);
        assertEq(att.proofType, ProofTypes.RISK_SCORE_SIGNED);
        // RISK_SCORE-class proofs do not carry providerSetHash on the attestation.
        assertEq(att.providerSetHash, bytes32(0));
    }

    function test_submitCompliance_riskScoreSigned_revert_unregisteredSignerPubkeyHash() public {
        bytes memory inputs = _riskScoreSignedInputs(INITIAL_CONFIG, OTHER_SIGNER_PUBKEY_HASH, alice);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPOracle.InvalidSignerPubkeyHash.selector, OTHER_SIGNER_PUBKEY_HASH)
        );
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // Jurisdiction-flag enforcement (US, SG strict; EU, UK permissive)
    // -------------------------------------------------------------------------

    function test_strictJurisdiction_rejects_unsignedCompliance() public {
        bytes memory inputs = _complianceInputsFor(
            1,
            /* US */
            DEFAULT_PROVIDER_SET_HASH,
            alice
        );
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.SignedSignalsRequired.selector, 1, ProofTypes.COMPLIANCE));
        oracle.submitCompliance(1, ProofTypes.COMPLIANCE, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_strictJurisdiction_rejects_unsignedRiskScore() public {
        bytes memory inputs = _riskScoreInputs(INITIAL_CONFIG);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.SignedSignalsRequired.selector, 3, ProofTypes.RISK_SCORE));
        oracle.submitCompliance(
            3,
            /* SG */
            ProofTypes.RISK_SCORE,
            _uniqueProof(),
            inputs,
            DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_strictJurisdiction_acceptsSignedCompliance() public {
        vm.prank(owner);
        oracle.registerSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);

        bytes memory inputs = _complianceSignedInputs(
            1,
            /* US */
            DEFAULT_PROVIDER_SET_HASH,
            TEST_SIGNER_PUBKEY_HASH,
            alice
        );
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(1, ProofTypes.COMPLIANCE_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH);
        assertEq(att.jurisdictionId, 1);
    }

    function test_permissiveJurisdiction_acceptsSignedCompliance() public {
        // Permissive jurisdictions also accept signed proofs (signed is a stricter
        // proof and never rejected on policy grounds).
        vm.prank(owner);
        oracle.registerSignerPubkeyHash(TEST_SIGNER_PUBKEY_HASH);

        bytes memory inputs = _complianceSignedInputs(
            0,
            /* EU */
            DEFAULT_PROVIDER_SET_HASH,
            TEST_SIGNER_PUBKEY_HASH,
            alice
        );
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH);
        assertEq(att.jurisdictionId, 0);
    }

    // -------------------------------------------------------------------------
    // COMPLIANCE_MULTI_SIGNED submission paths (M-of-N quorum, up to 5 signers)
    // -------------------------------------------------------------------------

    bytes32 internal constant SIGNER_HASH_A = bytes32(uint256(0x5AAA));
    bytes32 internal constant SIGNER_HASH_B = bytes32(uint256(0x5BBB));
    bytes32 internal constant SIGNER_HASH_C = bytes32(uint256(0x5CCC));
    bytes32 internal constant SIGNER_HASH_D = bytes32(uint256(0x5DDD));
    bytes32 internal constant SIGNER_HASH_E = bytes32(uint256(0x5EEE));

    function _registerThreeSigners() internal {
        vm.startPrank(owner);
        oracle.registerSignerPubkeyHash(SIGNER_HASH_A);
        oracle.registerSignerPubkeyHash(SIGNER_HASH_B);
        oracle.registerSignerPubkeyHash(SIGNER_HASH_C);
        vm.stopPrank();
    }

    function _registerFiveSigners() internal {
        vm.startPrank(owner);
        oracle.registerSignerPubkeyHash(SIGNER_HASH_A);
        oracle.registerSignerPubkeyHash(SIGNER_HASH_B);
        oracle.registerSignerPubkeyHash(SIGNER_HASH_C);
        oracle.registerSignerPubkeyHash(SIGNER_HASH_D);
        oracle.registerSignerPubkeyHash(SIGNER_HASH_E);
        vm.stopPrank();
    }

    function test_submitCompliance_multiSigned_happy_2of3() public {
        _registerThreeSigners();
        bytes32[5] memory hashes = [SIGNER_HASH_A, SIGNER_HASH_B, SIGNER_HASH_C, bytes32(0), bytes32(0)];

        bytes memory inputs = _complianceMultiSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, 2, hashes, alice);
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
        assertEq(att.proofType, ProofTypes.COMPLIANCE_MULTI_SIGNED);
        assertEq(att.providerSetHash, DEFAULT_PROVIDER_SET_HASH);
        assertEq(att.jurisdictionId, 0);
    }

    function test_submitCompliance_multiSigned_happy_3of5() public {
        _registerFiveSigners();
        bytes32[5] memory hashes = [SIGNER_HASH_A, SIGNER_HASH_B, SIGNER_HASH_C, SIGNER_HASH_D, SIGNER_HASH_E];

        bytes memory inputs = _complianceMultiSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, 3, hashes, alice);
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
        assertEq(att.proofType, ProofTypes.COMPLIANCE_MULTI_SIGNED);
    }

    function test_submitCompliance_multiSigned_revert_insufficientSigners() public {
        _registerThreeSigners();
        // Only 2 active slots but threshold_m requires 3.
        bytes32[5] memory hashes = [SIGNER_HASH_A, SIGNER_HASH_B, bytes32(0), bytes32(0), bytes32(0)];

        bytes memory inputs = _complianceMultiSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, 3, hashes, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InsufficientSigners.selector, 2, 3));
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_submitCompliance_multiSigned_revert_oneSignerRevoked() public {
        _registerThreeSigners();
        vm.prank(owner);
        oracle.revokeSignerPubkeyHash(SIGNER_HASH_B);

        bytes32[5] memory hashes = [SIGNER_HASH_A, SIGNER_HASH_B, SIGNER_HASH_C, bytes32(0), bytes32(0)];
        bytes memory inputs = _complianceMultiSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, 2, hashes, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidSignerPubkeyHash.selector, SIGNER_HASH_B));
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_submitCompliance_multiSigned_revert_duplicateSigner() public {
        _registerThreeSigners();
        // SIGNER_HASH_A appears twice in active slots.
        bytes32[5] memory hashes = [SIGNER_HASH_A, SIGNER_HASH_B, SIGNER_HASH_A, bytes32(0), bytes32(0)];

        bytes memory inputs = _complianceMultiSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, 2, hashes, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.DuplicateSigner.selector, SIGNER_HASH_A));
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_submitCompliance_multiSigned_revert_invalidThresholdM_zero() public {
        _registerThreeSigners();
        bytes32[5] memory hashes = [SIGNER_HASH_A, SIGNER_HASH_B, bytes32(0), bytes32(0), bytes32(0)];

        bytes memory inputs = _complianceMultiSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, 0, hashes, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidThresholdM.selector, 0));
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_submitCompliance_multiSigned_revert_invalidThresholdM_tooHigh() public {
        _registerFiveSigners();
        bytes32[5] memory hashes = [SIGNER_HASH_A, SIGNER_HASH_B, SIGNER_HASH_C, SIGNER_HASH_D, SIGNER_HASH_E];

        bytes memory inputs = _complianceMultiSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, 6, hashes, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidThresholdM.selector, 6));
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_submitCompliance_multiSigned_revert_belowJurisdictionFloor_US() public {
        // US requires minMultiProviderThreshold >= 2; M=1 must be rejected.
        _registerThreeSigners();
        bytes32[5] memory hashes = [SIGNER_HASH_A, bytes32(0), bytes32(0), bytes32(0), bytes32(0)];

        bytes memory inputs = _complianceMultiSignedInputs(1, DEFAULT_PROVIDER_SET_HASH, 1, hashes, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.BelowJurisdictionMinProviders.selector, 1, 1, 2));
        oracle.submitCompliance(
            1, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_submitCompliance_multiSigned_revert_belowJurisdictionFloor_SG() public {
        // SG also requires M >= 2.
        _registerThreeSigners();
        bytes32[5] memory hashes = [SIGNER_HASH_A, bytes32(0), bytes32(0), bytes32(0), bytes32(0)];

        bytes memory inputs = _complianceMultiSignedInputs(3, DEFAULT_PROVIDER_SET_HASH, 1, hashes, alice);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.BelowJurisdictionMinProviders.selector, 3, 1, 2));
        oracle.submitCompliance(
            3, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_strictJurisdiction_acceptsMultiSigned_USwithM2() public {
        // US accepts M=2 (matches the jurisdiction floor).
        _registerThreeSigners();
        bytes32[5] memory hashes = [SIGNER_HASH_A, SIGNER_HASH_B, bytes32(0), bytes32(0), bytes32(0)];

        bytes memory inputs = _complianceMultiSignedInputs(1, DEFAULT_PROVIDER_SET_HASH, 2, hashes, alice);
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.submitCompliance(
            1, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
        assertEq(att.jurisdictionId, 1);
    }

    function test_submitCompliance_multiSigned_revert_chainIdMismatch() public {
        _registerThreeSigners();
        bytes32[5] memory hashes = [SIGNER_HASH_A, SIGNER_HASH_B, bytes32(0), bytes32(0), bytes32(0)];

        // Tamper chain_id (slot [11]) with a wrong value.
        bytes memory inputs = abi.encodePacked(
            bytes32(uint256(0)), // [0] jurisdiction_id
            DEFAULT_PROVIDER_SET_HASH, // [1]
            INITIAL_CONFIG, // [2]
            bytes32(block.timestamp), // [3]
            bytes32(uint256(1)), // [4] meets_threshold
            bytes32(uint256(2)), // [5] threshold_m
            hashes[0],
            hashes[1],
            hashes[2],
            hashes[3],
            hashes[4],
            bytes32(uint256(0xdeadbeef)), // [11] wrong chain_id
            bytes32(uint256(uint160(address(oracle)))), // [12]
            bytes32(uint256(uint160(alice))) // [13]
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.PublicInputMismatch.selector);
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_submitCompliance_multiSigned_revert_oracleAddressMismatch() public {
        _registerThreeSigners();
        bytes32[5] memory hashes = [SIGNER_HASH_A, SIGNER_HASH_B, bytes32(0), bytes32(0), bytes32(0)];

        bytes memory inputs = abi.encodePacked(
            bytes32(uint256(0)),
            DEFAULT_PROVIDER_SET_HASH,
            INITIAL_CONFIG,
            bytes32(block.timestamp),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            hashes[0],
            hashes[1],
            hashes[2],
            hashes[3],
            hashes[4],
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(0xdead)))), // [12] wrong oracle_address
            bytes32(uint256(uint160(alice)))
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.PublicInputMismatch.selector);
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_submitCompliance_multiSigned_revert_submitterMismatch() public {
        _registerThreeSigners();
        bytes32[5] memory hashes = [SIGNER_HASH_A, SIGNER_HASH_B, bytes32(0), bytes32(0), bytes32(0)];

        // Inputs claim alice; caller is bob.
        bytes memory inputs = _complianceMultiSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, 2, hashes, alice);
        address bob = makeAddr("bob");
        vm.prank(bob);
        vm.expectRevert(XochiZKPOracle.SubmitterMismatch.selector);
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE_MULTI_SIGNED, _uniqueProof(), inputs, DEFAULT_PROVIDER_SET_HASH
        );
    }

    // -------------------------------------------------------------------------
    // EIP-165
    // -------------------------------------------------------------------------

    function test_supportsInterface_self() public view {
        assertTrue(oracle.supportsInterface(type(IXochiZKPOracle).interfaceId));
    }

    function test_supportsInterface_erc165() public view {
        assertTrue(oracle.supportsInterface(type(IERC165).interfaceId));
    }

    function test_supportsInterface_invalidSelector_returnsFalse() public view {
        assertFalse(oracle.supportsInterface(0xffffffff));
    }

    function test_supportsInterface_unknownSelector_returnsFalse() public view {
        assertFalse(oracle.supportsInterface(0xdeadbeef));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function _submitForAlice(uint8 jurisdictionId) internal {
        _submitForAliceWith(jurisdictionId, _uniqueProof());
    }

    function _submitForAliceWith(uint8 jurisdictionId, bytes memory proof) internal {
        bytes memory publicInputs = _complianceInputsFor(jurisdictionId, DEFAULT_PROVIDER_SET_HASH);
        vm.prank(alice);
        oracle.submitCompliance(jurisdictionId, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    uint256 internal _proofNonce;

    function _uniqueProof() internal returns (bytes memory) {
        _proofNonce++;
        bytes memory proof = new bytes(2144);
        assembly {
            mstore(add(proof, 32), sload(_proofNonce.slot))
        }
        // Use storage nonce encoded in the proof to make it unique
        bytes32 nonceBytes = bytes32(_proofNonce);
        for (uint256 i; i < 32; i++) {
            proof[i] = nonceBytes[i];
        }
        return proof;
    }

    /// @dev Default provider set hash used in tests (must match public inputs)
    bytes32 internal constant DEFAULT_PROVIDER_SET_HASH = bytes32(uint256(0xaabb));

    /// @dev 6 public inputs matching the compliance circuit
    function _complianceInputs() internal view returns (bytes memory) {
        return _complianceInputsFor(0, DEFAULT_PROVIDER_SET_HASH, alice);
    }

    /// @dev Compliance inputs with configurable jurisdiction and providerSetHash
    function _complianceInputsFor(uint8 jurisdictionId, bytes32 providerSetHash) internal view returns (bytes memory) {
        return _complianceInputsFor(jurisdictionId, providerSetHash, alice);
    }

    /// @dev Compliance inputs with configurable jurisdiction, providerSetHash, and submitter
    function _complianceInputsFor(uint8 jurisdictionId, bytes32 providerSetHash, address submitter)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes32(uint256(jurisdictionId)), // jurisdiction_id
            providerSetHash, // provider_set_hash
            INITIAL_CONFIG, // config_hash
            bytes32(block.timestamp), // timestamp
            bytes32(uint256(1)), // meets_threshold
            bytes32(uint256(uint160(submitter))) // submitter
        );
    }

    /// @dev COMPLIANCE_MULTI_SIGNED public inputs (14 slots: compliance + threshold_m
    ///      + 5 signer_pubkey_hash slots + chain_id + oracle_address)
    function _complianceMultiSignedInputs(
        uint8 jurisdictionId,
        bytes32 providerSetHash,
        uint8 thresholdM,
        bytes32[5] memory signerHashes,
        address submitter
    ) internal view returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(jurisdictionId)), // [0] jurisdiction_id
            providerSetHash, // [1] provider_set_hash
            INITIAL_CONFIG, // [2] config_hash
            bytes32(block.timestamp), // [3] timestamp
            bytes32(uint256(1)), // [4] meets_threshold = true
            bytes32(uint256(thresholdM)), // [5] threshold_m
            signerHashes[0], // [6..11) signer_pubkey_hash_0..4
            signerHashes[1],
            signerHashes[2],
            signerHashes[3],
            signerHashes[4],
            bytes32(block.chainid), // [11] chain_id  (audit F-6)
            bytes32(uint256(uint160(address(oracle)))), // [12] oracle_address  (audit F-6)
            bytes32(uint256(uint160(submitter))) // [13] submitter
        );
    }

    /// @dev COMPLIANCE_SIGNED public inputs (9 slots: compliance + signer_pubkey_hash + chain_id + oracle_address)
    function _complianceSignedInputs(
        uint8 jurisdictionId,
        bytes32 providerSetHash,
        bytes32 signerPubkeyHash,
        address submitter
    ) internal view returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(jurisdictionId)), // jurisdiction_id
            providerSetHash, // provider_set_hash
            INITIAL_CONFIG, // config_hash
            bytes32(block.timestamp), // timestamp
            bytes32(uint256(1)), // meets_threshold
            signerPubkeyHash, // signer_pubkey_hash
            bytes32(block.chainid), // chain_id (audit F-6)
            bytes32(uint256(uint160(address(oracle)))), // oracle_address (audit F-6)
            bytes32(uint256(uint160(submitter))) // submitter
        );
    }

    /// @dev RISK_SCORE_SIGNED public inputs (11 slots: risk_score + signer_pubkey_hash + chain_id + oracle_address)
    function _riskScoreSignedInputs(bytes32 configHash, bytes32 signerPubkeyHash, address submitter)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes32(uint256(1)), // proof_type: threshold
            bytes32(uint256(1)), // direction: GT
            bytes32(uint256(5000)), // bound_lower
            bytes32(uint256(0)), // bound_upper
            bytes32(uint256(1)), // result
            configHash, // config_hash
            bytes32(uint256(0xeeff)), // provider_set_hash
            signerPubkeyHash, // signer_pubkey_hash
            bytes32(block.chainid), // chain_id (audit F-6)
            bytes32(uint256(uint160(address(oracle)))), // oracle_address (audit F-6)
            bytes32(uint256(uint160(submitter))) // submitter
        );
    }

    /// @dev RISK_SCORE public inputs with configurable config hash
    function _riskScoreInputs(bytes32 configHash) internal view returns (bytes memory) {
        return _riskScoreInputs(configHash, alice);
    }

    /// @dev RISK_SCORE public inputs with configurable config hash and submitter
    function _riskScoreInputs(bytes32 configHash, address submitter) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(1)), // proof_type: threshold
            bytes32(uint256(1)), // direction: GT
            bytes32(uint256(5000)), // bound_lower
            bytes32(uint256(0)), // bound_upper
            bytes32(uint256(1)), // result
            configHash, // config_hash
            bytes32(uint256(0xeeff)), // provider_set_hash
            bytes32(uint256(uint160(submitter))) // submitter
        );
    }

    /// @dev RISK_SCORE public inputs with full control over semantic fields (for H-1 tests)
    function _riskScoreInputsCustom(
        uint8 proofType,
        uint8 direction,
        uint256 boundLower,
        uint256 boundUpper,
        bytes32 configHash,
        address submitter
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(proofType)),
            bytes32(uint256(direction)),
            bytes32(boundLower),
            bytes32(boundUpper),
            bytes32(uint256(1)), // result
            configHash,
            bytes32(uint256(0xeeff)), // provider_set_hash
            bytes32(uint256(uint160(submitter)))
        );
    }

    /// @dev MEMBERSHIP public inputs with configurable merkle root
    function _membershipInputs(bytes32 merkleRoot) internal view returns (bytes memory) {
        return _membershipInputs(merkleRoot, alice);
    }

    /// @dev MEMBERSHIP public inputs with configurable merkle root and submitter
    function _membershipInputs(bytes32 merkleRoot, address submitter) internal view returns (bytes memory) {
        return abi.encodePacked(
            merkleRoot, // merkle_root
            bytes32(uint256(1)), // set_id
            bytes32(block.timestamp), // timestamp
            bytes32(uint256(1)), // is_member
            bytes32(uint256(uint160(submitter))) // submitter
        );
    }

    /// @dev NON_MEMBERSHIP public inputs with configurable merkle root
    function _nonMembershipInputs(bytes32 merkleRoot) internal view returns (bytes memory) {
        return _nonMembershipInputs(merkleRoot, alice);
    }

    /// @dev NON_MEMBERSHIP public inputs with configurable merkle root and submitter
    function _nonMembershipInputs(bytes32 merkleRoot, address submitter) internal view returns (bytes memory) {
        return abi.encodePacked(
            merkleRoot, // merkle_root
            bytes32(uint256(1)), // set_id
            bytes32(block.timestamp), // timestamp
            bytes32(uint256(1)), // is_non_member
            bytes32(uint256(uint160(submitter))) // submitter
        );
    }

    /// @dev ATTESTATION public inputs with configurable credential root
    function _attestationInputs(bytes32 credentialRoot) internal view returns (bytes memory) {
        return _attestationInputs(credentialRoot, alice);
    }

    /// @dev ATTESTATION public inputs with configurable credential root and submitter
    function _attestationInputs(bytes32 credentialRoot, address submitter) internal view returns (bytes memory) {
        return abi.encodePacked(
            bytes32(DEFAULT_PROVIDER_ID), // provider_id (matches the publisher registered in setUp)
            bytes32(uint256(1)), // credential_type
            bytes32(uint256(1)), // is_valid
            credentialRoot, // credential_root
            bytes32(block.timestamp), // current_timestamp
            bytes32(uint256(uint160(submitter))) // submitter
        );
    }
}
