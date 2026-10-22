// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {ERC8262Oracle} from "../src/ERC8262Oracle.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";
import {OracleTestBase} from "./utils/OracleTestBase.sol";

/// @dev Rejection tests for ERC8262Oracle's public-input validators, one per check
///      and proof type. Each test starts from inputs the Oracle accepts and breaks one
///      field (or one piece of registry state), so it pins that check at that call
///      site. `scripts/mutate-validators.py` (CI job "Validator mutation") fails when
///      a validator check can be deleted with every test still passing; a new case
///      for this file is usually the fix.
contract ValidatorChecksTest is OracleTestBase {
    address internal mallory = makeAddr("mallory");

    /// @dev Signer keys for the signed types, registered to providers outside
    ///      INITIAL_CONFIG's expansion ({DEFAULT_PROVIDER_ID}), so denying the config's
    ///      provider leaves the signers authorized.
    bytes32 internal constant SIGNER_A = bytes32(uint256(0x51A));
    bytes32 internal constant SIGNER_B = bytes32(uint256(0x51B));

    bytes32 internal constant UNKNOWN_CONFIG = keccak256("validator-checks-unregistered-config");
    bytes32 internal constant OTHER_PROVIDER_SET = bytes32(uint256(0xdead));
    bytes32 internal constant MERKLE_ROOT = keccak256("validator-checks-merkle-root");
    bytes32 internal constant CREDENTIAL_ROOT = keccak256("validator-checks-credential-root");
    uint256 internal constant T0 = 1_700_000_000;

    // Word indices into the public inputs (each input is one 32-byte word).
    uint256 internal constant COMPLIANCE_CONFIG = 2;
    uint256 internal constant COMPLIANCE_TIMESTAMP = 3;
    uint256 internal constant COMPLIANCE_RESULT = 4;
    uint256 internal constant RISK_DIRECTION = 1;
    uint256 internal constant RISK_RESULT = 4;
    uint256 internal constant RISK_CONFIG = 5;
    uint256 internal constant ATTESTATION_PROVIDER = 0;
    uint256 internal constant ATTESTATION_TIMESTAMP = 4;
    uint256 internal constant SET_TIMESTAMP = 2;

    function setUp() public {
        vm.warp(T0);
        _setUpOracle();
        vm.startPrank(owner);
        oracle.registerSignerPubkeyHash(SIGNER_A, 1);
        oracle.registerSignerPubkeyHash(SIGNER_B, 2);
        oracle.registerMerkleRoot(ProofTypes.MEMBERSHIP, MERKLE_ROOT);
        oracle.registerMerkleRoot(ProofTypes.NON_MEMBERSHIP, MERKLE_ROOT);
        vm.stopPrank();
        _publishCredentialRoot(CREDENTIAL_ROOT);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// @dev Overwrite public input `index` in place and return the same buffer.
    function _setWord(bytes memory inputs, uint256 index, bytes32 value) internal pure returns (bytes memory) {
        assembly {
            mstore(add(inputs, mul(add(index, 1), 32)), value)
        }
        return inputs;
    }

    /// @dev Submit as alice. Callers arm `vm.expectRevert` first.
    function _submit(uint8 jurisdictionId, uint8 proofType, bytes memory inputs, bytes32 providerSetHash) internal {
        bytes memory proof = _uniqueProof();
        vm.prank(alice);
        oracle.submitCompliance(jurisdictionId, proofType, proof, inputs, providerSetHash);
    }

    function _patternInputs(address submitter) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(1)), // analysis_type: structuring
            bytes32(uint256(1)), // result
            bytes32(uint256(10000)), // reporting_threshold (registered by _setUpOracle)
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0xabcd)), // tx_set_hash
            bytes32(uint256(uint160(submitter))),
            bytes32(0) // settlement_root
        );
    }

    function _signedInputs() internal view returns (bytes memory) {
        return _complianceSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, SIGNER_A, alice);
    }

    function _multiSignedInputs() internal view returns (bytes memory) {
        bytes32[5] memory signers = [SIGNER_A, SIGNER_B, bytes32(0), bytes32(0), bytes32(0)];
        return _complianceMultiSignedInputs(0, DEFAULT_PROVIDER_SET_HASH, 2, signers, alice);
    }

    function _denyConfigProvider() internal {
        vm.prank(owner);
        oracle.denyProvider(DEFAULT_PROVIDER_ID);
    }

    // -------------------------------------------------------------------------
    // Unsigned types: submitter binding and timestamps
    // -------------------------------------------------------------------------

    function test_compliance_revert_submitterMismatch() public {
        bytes memory inputs = _complianceInputsFor(0, DEFAULT_PROVIDER_SET_HASH, mallory);
        vm.expectRevert(ERC8262Oracle.SubmitterMismatch.selector);
        _submit(0, ProofTypes.COMPLIANCE, inputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_riskScore_revert_submitterMismatch() public {
        vm.expectRevert(ERC8262Oracle.SubmitterMismatch.selector);
        _submit(0, ProofTypes.RISK_SCORE, _riskScoreInputs(INITIAL_CONFIG, mallory), bytes32(0));
    }

    function test_pattern_revert_submitterMismatch() public {
        vm.expectRevert(ERC8262Oracle.SubmitterMismatch.selector);
        _submit(0, ProofTypes.PATTERN, _patternInputs(mallory), bytes32(0));
    }

    function test_membership_revert_submitterMismatch() public {
        vm.expectRevert(ERC8262Oracle.SubmitterMismatch.selector);
        _submit(0, ProofTypes.MEMBERSHIP, _membershipInputs(MERKLE_ROOT, mallory), bytes32(0));
    }

    function test_nonMembership_revert_futureTimestamp() public {
        bytes memory inputs = _setWord(_nonMembershipInputs(MERKLE_ROOT), SET_TIMESTAMP, bytes32(T0 + 1));
        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.ProofTimestampInFuture.selector, T0 + 1, T0));
        _submit(0, ProofTypes.NON_MEMBERSHIP, inputs, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // ATTESTATION: provider id, credential root lifecycle, timestamp, submitter
    // -------------------------------------------------------------------------

    function test_attestation_revert_zeroProviderId() public {
        bytes memory inputs = _setWord(_attestationInputs(CREDENTIAL_ROOT), ATTESTATION_PROVIDER, bytes32(0));
        vm.expectRevert(ERC8262Oracle.InvalidProviderId.selector);
        _submit(0, ProofTypes.ATTESTATION, inputs, bytes32(0));
    }

    function test_attestation_revert_revokedRoot() public {
        vm.prank(owner);
        oracle.revokeCredentialRoot(CREDENTIAL_ROOT);

        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.CredentialRootExpired.selector, CREDENTIAL_ROOT, T0));
        _submit(0, ProofTypes.ATTESTATION, _attestationInputs(CREDENTIAL_ROOT), bytes32(0));
    }

    function test_attestation_revert_rootPastTtl() public {
        vm.warp(T0 + oracle.CREDENTIAL_ROOT_TTL() + 1);
        // Inputs dated now: only the root's age is wrong.
        bytes memory inputs = _attestationInputs(CREDENTIAL_ROOT);

        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.CredentialRootExpired.selector, CREDENTIAL_ROOT, T0));
        _submit(0, ProofTypes.ATTESTATION, inputs, bytes32(0));
    }

    function test_attestation_revert_rootOfOtherProvider() public {
        uint256 otherProvider = DEFAULT_PROVIDER_ID + 1;
        bytes memory inputs =
            _setWord(_attestationInputs(CREDENTIAL_ROOT), ATTESTATION_PROVIDER, bytes32(otherProvider));
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC8262Oracle.CredentialRootProviderMismatch.selector, DEFAULT_PROVIDER_ID, otherProvider
            )
        );
        _submit(0, ProofTypes.ATTESTATION, inputs, bytes32(0));
    }

    function test_attestation_revert_futureTimestamp() public {
        bytes memory inputs = _setWord(_attestationInputs(CREDENTIAL_ROOT), ATTESTATION_TIMESTAMP, bytes32(T0 + 1));
        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.ProofTimestampInFuture.selector, T0 + 1, T0));
        _submit(0, ProofTypes.ATTESTATION, inputs, bytes32(0));
    }

    function test_attestation_revert_submitterMismatch() public {
        vm.expectRevert(ERC8262Oracle.SubmitterMismatch.selector);
        _submit(0, ProofTypes.ATTESTATION, _attestationInputs(CREDENTIAL_ROOT, mallory), bytes32(0));
    }

    // -------------------------------------------------------------------------
    // COMPLIANCE_SIGNED (0x07)
    // -------------------------------------------------------------------------

    function test_complianceSigned_revert_jurisdictionMismatch() public {
        vm.expectRevert(ERC8262Oracle.PublicInputMismatch.selector);
        _submit(2, ProofTypes.COMPLIANCE_SIGNED, _signedInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    function test_complianceSigned_revert_providerSetMismatch() public {
        vm.expectRevert(ERC8262Oracle.PublicInputMismatch.selector);
        _submit(0, ProofTypes.COMPLIANCE_SIGNED, _signedInputs(), OTHER_PROVIDER_SET);
    }

    function test_complianceSigned_revert_unknownConfig() public {
        bytes memory inputs = _setWord(_signedInputs(), COMPLIANCE_CONFIG, UNKNOWN_CONFIG);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.InvalidConfigHash.selector, UNKNOWN_CONFIG));
        _submit(0, ProofTypes.COMPLIANCE_SIGNED, inputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_complianceSigned_revert_negativeResult() public {
        bytes memory inputs = _setWord(_signedInputs(), COMPLIANCE_RESULT, bytes32(0));
        vm.expectRevert(ERC8262Oracle.ProofResultNegative.selector);
        _submit(0, ProofTypes.COMPLIANCE_SIGNED, inputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_complianceSigned_revert_deniedConfigProvider() public {
        _denyConfigProvider();
        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.ProviderDenied.selector, DEFAULT_PROVIDER_ID));
        _submit(0, ProofTypes.COMPLIANCE_SIGNED, _signedInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    function test_complianceSigned_revert_futureTimestamp() public {
        bytes memory inputs = _setWord(_signedInputs(), COMPLIANCE_TIMESTAMP, bytes32(T0 + 1));
        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.ProofTimestampInFuture.selector, T0 + 1, T0));
        _submit(0, ProofTypes.COMPLIANCE_SIGNED, inputs, DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // COMPLIANCE_MULTI_SIGNED (0x09)
    // -------------------------------------------------------------------------

    function test_multiSigned_revert_jurisdictionMismatch() public {
        vm.expectRevert(ERC8262Oracle.PublicInputMismatch.selector);
        _submit(2, ProofTypes.COMPLIANCE_MULTI_SIGNED, _multiSignedInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    function test_multiSigned_revert_providerSetMismatch() public {
        vm.expectRevert(ERC8262Oracle.PublicInputMismatch.selector);
        _submit(0, ProofTypes.COMPLIANCE_MULTI_SIGNED, _multiSignedInputs(), OTHER_PROVIDER_SET);
    }

    function test_multiSigned_revert_unknownConfig() public {
        bytes memory inputs = _setWord(_multiSignedInputs(), COMPLIANCE_CONFIG, UNKNOWN_CONFIG);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.InvalidConfigHash.selector, UNKNOWN_CONFIG));
        _submit(0, ProofTypes.COMPLIANCE_MULTI_SIGNED, inputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_multiSigned_revert_negativeResult() public {
        bytes memory inputs = _setWord(_multiSignedInputs(), COMPLIANCE_RESULT, bytes32(0));
        vm.expectRevert(ERC8262Oracle.ProofResultNegative.selector);
        _submit(0, ProofTypes.COMPLIANCE_MULTI_SIGNED, inputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_multiSigned_revert_deniedConfigProvider() public {
        _denyConfigProvider();
        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.ProviderDenied.selector, DEFAULT_PROVIDER_ID));
        _submit(0, ProofTypes.COMPLIANCE_MULTI_SIGNED, _multiSignedInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    function test_multiSigned_revert_futureTimestamp() public {
        bytes memory inputs = _setWord(_multiSignedInputs(), COMPLIANCE_TIMESTAMP, bytes32(T0 + 1));
        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.ProofTimestampInFuture.selector, T0 + 1, T0));
        _submit(0, ProofTypes.COMPLIANCE_MULTI_SIGNED, inputs, DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // RISK_SCORE_SIGNED (0x08)
    // -------------------------------------------------------------------------

    function test_riskScoreSigned_revert_negativeResult() public {
        bytes memory inputs = _setWord(_riskScoreSignedInputs(INITIAL_CONFIG, SIGNER_A, alice), RISK_RESULT, 0);
        vm.expectRevert(ERC8262Oracle.ProofResultNegative.selector);
        _submit(0, ProofTypes.RISK_SCORE_SIGNED, inputs, bytes32(0));
    }

    function test_riskScoreSigned_revert_unknownConfig() public {
        bytes memory inputs =
            _setWord(_riskScoreSignedInputs(INITIAL_CONFIG, SIGNER_A, alice), RISK_CONFIG, UNKNOWN_CONFIG);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.InvalidConfigHash.selector, UNKNOWN_CONFIG));
        _submit(0, ProofTypes.RISK_SCORE_SIGNED, inputs, bytes32(0));
    }

    function test_riskScoreSigned_revert_deniedConfigProvider() public {
        _denyConfigProvider();
        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.ProviderDenied.selector, DEFAULT_PROVIDER_ID));
        _submit(0, ProofTypes.RISK_SCORE_SIGNED, _riskScoreSignedInputs(INITIAL_CONFIG, SIGNER_A, alice), bytes32(0));
    }

    function test_riskScoreSigned_revert_submitterMismatch() public {
        vm.expectRevert(ERC8262Oracle.SubmitterMismatch.selector);
        _submit(0, ProofTypes.RISK_SCORE_SIGNED, _riskScoreSignedInputs(INITIAL_CONFIG, SIGNER_A, mallory), bytes32(0));
    }

    function test_riskScoreSigned_revert_invalidDirection() public {
        bytes memory inputs =
            _setWord(_riskScoreSignedInputs(INITIAL_CONFIG, SIGNER_A, alice), RISK_DIRECTION, bytes32(uint256(3)));
        vm.expectRevert(abi.encodeWithSelector(ERC8262Oracle.InvalidRiskDirection.selector, 3));
        _submit(0, ProofTypes.RISK_SCORE_SIGNED, inputs, bytes32(0));
    }
}
