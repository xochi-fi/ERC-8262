// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IERC8262Oracle} from "./IERC8262Oracle.sol";

/// @title ISettlementRegistry -- Interface for linking sub-settlement compliance proofs to a trade
/// @notice Tracks multi-leg trade settlements where each sub-trade must have a verified compliance
///         attestation in the ERC-8262 Oracle before the trade can be finalized
interface ISettlementRegistry {
    /// @notice A registered trade awaiting sub-settlement completion
    struct Settlement {
        bytes32 tradeId;
        address subject; // address that registered the trade
        uint8 jurisdictionId;
        uint8 subTradeCount; // total sub-trades expected
        uint8 settledCount; // sub-trades settled so far
        uint256 createdAt;
        uint256 expiresAt;
        bool finalized;
    }

    /// @notice A single sub-settlement linked to a compliance proof
    struct SubSettlement {
        uint8 index; // sub-trade index within the trade
        bytes32 proofHash; // proof hash from the oracle
        uint256 settledAt; // block.timestamp when recorded
    }

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a new trade is registered
    event TradeRegistered(
        bytes32 indexed tradeId, address indexed subject, uint8 indexed jurisdictionId, uint8 subTradeCount
    );

    /// @notice Emitted when a sub-settlement is recorded against a trade
    event SubSettlementRecorded(bytes32 indexed tradeId, uint8 indexed index, bytes32 indexed proofHash);

    /// @notice Emitted when all sub-settlements are complete and the trade is finalized
    event TradeFinalized(bytes32 indexed tradeId, uint256 timestamp);

    /// @notice Emitted when a trade expires without finalization
    event TradeExpired(bytes32 indexed tradeId, uint256 timestamp);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error TradeAlreadyExists(bytes32 tradeId);
    error TradeNotFound(bytes32 tradeId);
    error SubTradeIndexOutOfBounds(uint8 index, uint8 subTradeCount);
    error SubTradeAlreadySettled(bytes32 tradeId, uint8 index);
    error NotTradeSubject(address caller, address subject);
    error TradeAlreadyFinalized(bytes32 tradeId);
    error TradeNotComplete(bytes32 tradeId, uint8 settledCount, uint8 subTradeCount);
    error AttestationNotFound(bytes32 proofHash);
    error SubjectMismatch(address expected, address actual);
    error JurisdictionMismatch(uint8 expected, uint8 actual);
    error TradeExpiredError(bytes32 tradeId);
    error TradeNotExpired(bytes32 tradeId);
    error PatternProofRequired(bytes32 tradeId);
    error InvalidSubTradeCount(uint8 count);
    error PatternPublicInputsMismatch(bytes32 expected, bytes32 actual);
    error PatternAnalysisTypeMismatch(uint256 expected, uint256 actual);
    /// @notice Raised when the pattern proof's `settlement_root` public input does
    ///         not match the keccak commitment over this trade's recorded
    ///         sub-settlement proof hashes (audit H-1).
    error SettlementRootMismatch(bytes32 expected, bytes32 actual);
    /// @notice Raised when the same pattern proof is presented to finalize more
    ///         than one trade (audit H-1 reuse-prevention).
    error PatternProofAlreadyUsed(bytes32 patternProofHash);
    /// @notice Raised when a sub-settlement proof is not one of the compliance
    ///         variants (COMPLIANCE / COMPLIANCE_SIGNED / COMPLIANCE_MULTI_SIGNED).
    /// @dev The registry advertises "verified compliance attestation" semantics; a
    ///      MEMBERSHIP/RISK_SCORE/PATTERN/etc. proof for the same subject and
    ///      jurisdiction would otherwise satisfy `recordSubSettlement` and silently
    ///      substitute a non-AML guarantee.
    error NonComplianceProofType(bytes32 proofHash, uint8 proofType);

    // -------------------------------------------------------------------------
    // Functions
    // -------------------------------------------------------------------------

    /// @notice Register a new multi-leg trade for settlement tracking
    /// @param tradeId Unique identifier for the trade
    /// @param jurisdictionId Jurisdiction for compliance verification
    /// @param subTradeCount Number of sub-trades (must be in [2, 100])
    function registerTrade(bytes32 tradeId, uint8 jurisdictionId, uint8 subTradeCount) external;

    /// @notice Record a sub-settlement by linking it to a verified compliance proof
    /// @param tradeId The trade to record against
    /// @param index The sub-trade index (0-based, must be < subTradeCount)
    /// @param proofHash The proof hash from a prior oracle submission
    function recordSubSettlement(bytes32 tradeId, uint8 index, bytes32 proofHash) external;

    /// @notice Finalize a trade after all sub-settlements are recorded
    /// @dev Requires a pattern detection proof of analysis_type=STRUCTURING for the subject.
    ///      The caller supplies the original public inputs so the registry can verify
    ///      keccak256(patternPublicInputs) matches the attestation's stored publicInputsHash,
    ///      then enforces analysis_type==1 (anti-structuring). VELOCITY/ROUND-AMOUNT proofs
    ///      are rejected.
    /// @param tradeId The trade to finalize
    /// @param patternProofHash Proof hash of a pattern detection proof for the subject
    /// @param patternPublicInputs Original public inputs used to generate the pattern proof
    function finalizeTrade(bytes32 tradeId, bytes32 patternProofHash, bytes calldata patternPublicInputs) external;

    /// @notice Expire a trade that has passed its expiry window without finalization
    /// @dev Permissionless -- anyone can call this after expiry
    /// @param tradeId The trade to expire
    function expireTrade(bytes32 tradeId) external;

    /// @notice Get a settlement record
    /// @param tradeId The trade to query
    /// @return settlement The settlement data
    function getSettlement(bytes32 tradeId) external view returns (Settlement memory settlement);

    /// @notice Get all recorded sub-settlements for a trade
    /// @param tradeId The trade to query
    /// @return subSettlements Array of recorded sub-settlements (excludes unset entries)
    function getSubSettlements(bytes32 tradeId) external view returns (SubSettlement[] memory subSettlements);

    /// @notice The oracle contract used for attestation lookups
    /// @return The oracle address
    function oracle() external view returns (IERC8262Oracle);
}
