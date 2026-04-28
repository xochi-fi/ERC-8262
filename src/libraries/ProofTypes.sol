// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

/// @title ProofTypes -- Proof type definitions for Xochi ZKP compliance oracle
/// @notice Defines the six proof types and their public input schemas.
///         Each proof type corresponds to a separate Noir circuit.
library ProofTypes {
    /// @notice Proof type identifiers (one per circuit)
    uint8 internal constant COMPLIANCE = 0x01; // compliance circuit
    uint8 internal constant RISK_SCORE = 0x02; // risk_score circuit
    uint8 internal constant PATTERN = 0x03; // pattern circuit
    uint8 internal constant ATTESTATION = 0x04; // attestation circuit
    uint8 internal constant MEMBERSHIP = 0x05; // membership circuit
    uint8 internal constant NON_MEMBERSHIP = 0x06; // non_membership circuit

    error InvalidProofType(uint8 proofType);
    error InvalidPublicInputLength(uint8 proofType, uint256 expected, uint256 actual);

    /// @notice Expected number of public inputs per proof type
    /// @dev Must match the `pub` parameters in each Noir circuit's main() function
    /// @param proofType The proof type identifier (0x01-0x06)
    /// @return count Number of bytes32 public inputs expected
    function expectedPublicInputCount(uint8 proofType) internal pure returns (uint256 count) {
        // compliance: jurisdiction_id, provider_set_hash, config_hash, timestamp, meets_threshold, submitter
        if (proofType == COMPLIANCE) return 6;
        // risk_score: proof_type, direction, bound_lower, bound_upper, result, config_hash, provider_set_hash, submitter
        if (proofType == RISK_SCORE) return 8;
        // pattern: analysis_type, result, reporting_threshold, time_window, tx_set_hash, submitter
        if (proofType == PATTERN) return 6;
        // attestation: provider_id, credential_type, is_valid, merkle_root, current_timestamp, submitter
        if (proofType == ATTESTATION) return 6;
        // membership: merkle_root, set_id, timestamp, is_member, submitter
        if (proofType == MEMBERSHIP) return 5;
        // non_membership: merkle_root, set_id, timestamp, is_non_member, submitter
        if (proofType == NON_MEMBERSHIP) return 5;
        revert InvalidProofType(proofType);
    }

    error UnalignedPublicInputs(uint256 length);

    /// @notice Validate that public inputs match expected count for a proof type
    function validatePublicInputs(uint8 proofType, bytes calldata publicInputs) internal pure {
        if (publicInputs.length % 32 != 0) revert UnalignedPublicInputs(publicInputs.length);
        uint256 expected = expectedPublicInputCount(proofType);
        uint256 actual = publicInputs.length / 32;
        if (actual != expected) {
            revert InvalidPublicInputLength(proofType, expected, actual);
        }
    }

    /// @notice Decode packed bytes into a bytes32 array for the verifier
    /// @dev Uses calldatacopy to batch-copy all slots in one operation instead of
    ///      per-slot calldata slicing. Saves ~60 gas per additional public input.
    function decodePublicInputs(bytes calldata packed) internal pure returns (bytes32[] memory inputs) {
        uint256 count = packed.length / 32;
        inputs = new bytes32[](count);
        /// @solidity memory-safe-assembly
        assembly {
            calldatacopy(add(inputs, 0x20), packed.offset, packed.length)
        }
    }

    /// @notice Check if a proof type is valid
    function isValidProofType(uint8 proofType) internal pure returns (bool valid) {
        return proofType >= COMPLIANCE && proofType <= NON_MEMBERSHIP;
    }
}
