// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {ERC8262Oracle} from "../../src/ERC8262Oracle.sol";
import {ERC8262Verifier} from "../../src/ERC8262Verifier.sol";
import {EIP712CredentialRoot} from "../../src/libraries/EIP712CredentialRoot.sol";
import {ProofTypes} from "../../src/libraries/ProofTypes.sol";
import {ERC8262TestBase} from "./ERC8262TestBase.sol";
import {PassingVerifier} from "./TestStubs.sol";

/// @dev Shared base for test suites that exercise ERC8262Oracle end-to-end.
///      Owns the oracle and verifier instances, the deterministic credential signer,
///      and the set of public-input builders for every proof type. Inheriting tests
///      call `_setUpOracle()` from their own `setUp()` to get a ready-to-use Oracle
///      registered with the stub verifier for all 9 proof types and seeded with a
///      default reporting threshold, publisher, and credential signer.
abstract contract OracleTestBase is ERC8262TestBase {
    ERC8262Oracle internal oracle;
    ERC8262Verifier internal verifier;
    PassingVerifier internal stubVerifier;

    address internal publisher = makeAddr("publisher");
    address internal credentialSignerAddr;

    bytes32 internal constant INITIAL_CONFIG = keccak256("initial-config");
    uint256 internal constant DEFAULT_PROVIDER_ID = 42;
    bytes32 internal constant DEFAULT_PROVIDER_SET_HASH = bytes32(uint256(0xaabb));

    /// @dev Deterministic test signing key for credential-root signatures (audit C-1).
    ///      Registered as the credential signer for `DEFAULT_PROVIDER_ID` in `_setUpOracle`.
    uint256 internal constant CREDENTIAL_SIGNER_KEY = uint256(keccak256("erc8262-test-credential-signer"));

    // Mirror of ERC8262Oracle internal constants for risk-score validation tests.
    uint8 internal constant RISK_PROOF_THRESHOLD = 0x01;
    uint8 internal constant RISK_PROOF_RANGE = 0x02;
    uint8 internal constant RISK_DIRECTION_GT = 1;
    uint8 internal constant RISK_DIRECTION_LT = 2;

    /// @dev Monotonic counter that lets `_uniqueProof()` emit a fresh 2144-byte proof
    ///      blob per call -- needed because the Oracle keys replay protection on the
    ///      keccak256 of (proof, proofType, chainid, oracle), so identical bytes from
    ///      different tests would collide.
    uint256 internal _proofNonce;

    /// @dev Default 1-element provider expansion used by tests that do not exercise
    ///      `denyProvider` semantics. Tests that need a different layout build their
    ///      own array inline and pass it to the Oracle constructor directly.
    function _defaultProviders() internal pure returns (uint256[] memory ps) {
        ps = new uint256[](1);
        ps[0] = DEFAULT_PROVIDER_ID;
    }

    /// @dev Standard setUp: deploy verifier + oracle, register the stub verifier for
    ///      every proof type (including signed variants), register the default reporting
    ///      threshold (for PATTERN tests), and seed the default attestation provider's
    ///      publisher and credential signing key.
    function _setUpOracle() internal {
        verifier = new ERC8262Verifier(owner);
        oracle = new ERC8262Oracle(address(verifier), owner, INITIAL_CONFIG, _defaultProviders());

        stubVerifier = new PassingVerifier();
        _registerAllVerifiers(verifier, address(stubVerifier), true);

        vm.startPrank(owner);
        oracle.registerReportingThreshold(bytes32(uint256(10000)));
        oracle.setProviderPublisher(DEFAULT_PROVIDER_ID, publisher);
        credentialSignerAddr = vm.addr(CREDENTIAL_SIGNER_KEY);
        oracle.setCredentialSigner(DEFAULT_PROVIDER_ID, credentialSignerAddr);
        vm.stopPrank();
    }

    // -------------------------------------------------------------------------
    // Proof bytes
    // -------------------------------------------------------------------------

    function _uniqueProof() internal returns (bytes memory) {
        _proofNonce++;
        bytes memory proof = new bytes(2144);
        bytes32 nonceBytes = bytes32(_proofNonce);
        for (uint256 i; i < 32; i++) {
            proof[i] = nonceBytes[i];
        }
        return proof;
    }

    // -------------------------------------------------------------------------
    // Credential roots (ATTESTATION setup)
    // -------------------------------------------------------------------------

    /// @dev Publish a credential root for the default provider.
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

    /// @dev Build an EIP-712 signature over a CredentialRootPublication.
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
    // submitCompliance helpers
    // -------------------------------------------------------------------------

    function _submitForAlice(uint8 jurisdictionId) internal {
        _submitForAliceWith(jurisdictionId, _uniqueProof());
    }

    function _submitForAliceWith(uint8 jurisdictionId, bytes memory proof) internal {
        bytes memory publicInputs = _complianceInputsFor(jurisdictionId, DEFAULT_PROVIDER_SET_HASH);
        vm.prank(alice);
        oracle.submitCompliance(jurisdictionId, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // Public-input builders (per proof type)
    // -------------------------------------------------------------------------

    /// @dev 6 public inputs matching the compliance circuit (jurisdiction = 0, alice submitter).
    function _complianceInputs() internal view returns (bytes memory) {
        return _complianceInputsFor(0, DEFAULT_PROVIDER_SET_HASH, alice);
    }

    /// @dev Compliance inputs with configurable jurisdiction and providerSetHash.
    function _complianceInputsFor(uint8 jurisdictionId, bytes32 providerSetHash) internal view returns (bytes memory) {
        return _complianceInputsFor(jurisdictionId, providerSetHash, alice);
    }

    /// @dev Compliance inputs with configurable jurisdiction, providerSetHash, and submitter.
    function _complianceInputsFor(uint8 jurisdictionId, bytes32 providerSetHash, address submitter)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes32(uint256(jurisdictionId)),
            providerSetHash,
            INITIAL_CONFIG,
            bytes32(block.timestamp),
            bytes32(uint256(1)), // meets_threshold
            bytes32(uint256(uint160(submitter)))
        );
    }

    /// @dev COMPLIANCE_SIGNED public inputs (9 slots: compliance + signer_pubkey_hash + chain_id + oracle_address).
    function _complianceSignedInputs(
        uint8 jurisdictionId,
        bytes32 providerSetHash,
        bytes32 signerPubkeyHash,
        address submitter
    ) internal view returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(jurisdictionId)),
            providerSetHash,
            INITIAL_CONFIG,
            bytes32(block.timestamp),
            bytes32(uint256(1)), // meets_threshold
            signerPubkeyHash,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(oracle)))),
            bytes32(uint256(uint160(submitter)))
        );
    }

    /// @dev COMPLIANCE_MULTI_SIGNED public inputs (14 slots: compliance + threshold_m
    ///      + 5 signer_pubkey_hash slots + chain_id + oracle_address).
    function _complianceMultiSignedInputs(
        uint8 jurisdictionId,
        bytes32 providerSetHash,
        uint8 thresholdM,
        bytes32[5] memory signerHashes,
        address submitter
    ) internal view returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(jurisdictionId)),
            providerSetHash,
            INITIAL_CONFIG,
            bytes32(block.timestamp),
            bytes32(uint256(1)), // meets_threshold
            bytes32(uint256(thresholdM)),
            signerHashes[0],
            signerHashes[1],
            signerHashes[2],
            signerHashes[3],
            signerHashes[4],
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(oracle)))),
            bytes32(uint256(uint160(submitter)))
        );
    }

    /// @dev RISK_SCORE public inputs with configurable config hash (submitter = alice).
    function _riskScoreInputs(bytes32 configHash) internal view returns (bytes memory) {
        return _riskScoreInputs(configHash, alice);
    }

    /// @dev RISK_SCORE public inputs with configurable config hash and submitter.
    function _riskScoreInputs(bytes32 configHash, address submitter) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(1)), // proof_type: threshold
            bytes32(uint256(1)), // direction: GT
            bytes32(uint256(5000)), // bound_lower
            bytes32(uint256(0)), // bound_upper
            bytes32(uint256(1)), // result
            configHash,
            bytes32(uint256(0xeeff)), // provider_set_hash
            bytes32(uint256(uint160(submitter)))
        );
    }

    /// @dev RISK_SCORE public inputs with full control over semantic fields (H-1 tests).
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

    /// @dev RISK_SCORE_SIGNED public inputs (11 slots: risk_score + signer_pubkey_hash + chain_id + oracle_address).
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
            configHash,
            bytes32(uint256(0xeeff)), // provider_set_hash
            signerPubkeyHash,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(oracle)))),
            bytes32(uint256(uint160(submitter)))
        );
    }

    /// @dev MEMBERSHIP public inputs with configurable merkle root (submitter = alice).
    function _membershipInputs(bytes32 merkleRoot) internal view returns (bytes memory) {
        return _membershipInputs(merkleRoot, alice);
    }

    /// @dev MEMBERSHIP public inputs with configurable merkle root and submitter.
    function _membershipInputs(bytes32 merkleRoot, address submitter) internal view returns (bytes memory) {
        return abi.encodePacked(
            merkleRoot,
            bytes32(uint256(1)), // set_id
            bytes32(block.timestamp),
            bytes32(uint256(1)), // is_member
            bytes32(uint256(uint160(submitter)))
        );
    }

    /// @dev NON_MEMBERSHIP public inputs with configurable merkle root (submitter = alice).
    function _nonMembershipInputs(bytes32 merkleRoot) internal view returns (bytes memory) {
        return _nonMembershipInputs(merkleRoot, alice);
    }

    /// @dev NON_MEMBERSHIP public inputs with configurable merkle root and submitter.
    function _nonMembershipInputs(bytes32 merkleRoot, address submitter) internal view returns (bytes memory) {
        return abi.encodePacked(
            merkleRoot,
            bytes32(uint256(1)), // set_id
            bytes32(block.timestamp),
            bytes32(uint256(1)), // is_non_member
            bytes32(uint256(uint160(submitter)))
        );
    }

    /// @dev ATTESTATION public inputs with configurable credential root (submitter = alice).
    function _attestationInputs(bytes32 credentialRoot) internal view returns (bytes memory) {
        return _attestationInputs(credentialRoot, alice);
    }

    /// @dev ATTESTATION public inputs with configurable credential root and submitter.
    function _attestationInputs(bytes32 credentialRoot, address submitter) internal view returns (bytes memory) {
        return abi.encodePacked(
            bytes32(DEFAULT_PROVIDER_ID),
            bytes32(uint256(1)), // credential_type
            bytes32(uint256(1)), // is_valid
            credentialRoot,
            bytes32(block.timestamp),
            bytes32(uint256(uint160(submitter)))
        );
    }
}
