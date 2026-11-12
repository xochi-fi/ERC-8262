// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IERC8262Oracle} from "./IERC8262Oracle.sol";

/// @title ISettlementRegistry -- Interface for linking sub-settlement compliance proofs to a trade
/// @notice Tracks multi-leg trade settlements where each sub-trade must have a verified compliance
///         attestation in the ERC-8262 Oracle before the trade can be finalized
interface ISettlementRegistry {
    /// @notice A registered trade awaiting sub-settlement completion
    /// @dev pending -> finalized (`finalizeTrade`), pending -> abandoned (`abandonTrade`), or
    ///      pending -> expired (`expireTrade`); `finalized` excludes both others. An expired
    ///      trade with a recorded leg stays unresolved, and blocks its subject's
    ///      `registerTrade`, until `abandonTrade` also marks it abandoned.
    struct Settlement {
        bytes32 tradeId;
        address subject; // address that registered the trade
        uint8 jurisdictionId;
        uint8 subTradeCount; // total sub-trades expected
        uint8 settledCount; // sub-trades settled so far
        uint8 openSlot; // index in the subject's open-trade table
        uint64 lastSettledAt; // block time of the latest recorded leg (0 before any)
        uint256 createdAt;
        uint256 expiresAt;
        bool finalized; // true only after a successful finalizeTrade
        bool expired; // true only after expireTrade closed the trade unfinalized
        bool abandoned; // true only after abandonTrade closed the trade unfinalized
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
    /// @param tradeRef Caller-chosen reference; `tradeId = computeTradeId(subject, tradeRef)`
    event TradeRegistered(
        bytes32 indexed tradeId,
        address indexed subject,
        uint8 indexed jurisdictionId,
        uint8 subTradeCount,
        bytes32 tradeRef
    );

    /// @notice Emitted when a sub-settlement is recorded against a trade
    event SubSettlementRecorded(bytes32 indexed tradeId, uint8 indexed index, bytes32 indexed proofHash);

    /// @notice Emitted when all sub-settlements are complete and the trade is finalized
    event TradeFinalized(bytes32 indexed tradeId, uint256 timestamp);

    /// @notice Emitted when a trade expires without finalization
    event TradeExpired(bytes32 indexed tradeId, uint256 timestamp);

    /// @notice Emitted when the subject closes a trade unfinalized
    /// @param patternProofHash STRUCTURING proof over the recorded legs; zero when none recorded
    event TradeAbandoned(bytes32 indexed tradeId, uint8 settledCount, bytes32 patternProofHash);

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
    /// @notice Leg attestation is past its oracle `expiresAt`.
    error AttestationExpired(bytes32 proofHash, uint256 expiresAt);
    error AttestationRevoked(bytes32 proofHash);
    /// @notice Leg attestation was recorded (Oracle submission time) before the trade was registered.
    error AttestationPredatesTrade(bytes32 proofHash, uint256 attestedAt, uint256 tradeCreatedAt);
    /// @notice The PATTERN proof's own `timestamp` public input predates the trade's last
    ///         recorded leg, so it cannot have analysed that leg.
    /// @dev `proofTimestamp` is public input 7, not the Oracle attestation time, which may be later.
    error PatternProofPredatesLastLeg(bytes32 proofHash, uint256 proofTimestamp, uint256 lastSettledAt);
    /// @notice The PATTERN proof's analysis window starts after the trade was registered, so
    ///         it cannot contain every leg.
    error PatternWindowExcludesTrade(bytes32 proofHash, uint256 windowStart, uint256 tradeCreatedAt);
    /// @notice Proof hash already backs a leg of this or any other trade.
    error DuplicateSubSettlementProof(bytes32 tradeId, bytes32 proofHash);
    error TradeAlreadyAbandoned(bytes32 tradeId);
    /// @notice Subject holds a lapsed trade with a recorded leg; resolve it with `abandonTrade`.
    error UnresolvedTrade(bytes32 tradeId);
    /// @notice Subject already holds the maximum number of open trades.
    error OpenTradeLimit(address subject);

    // -------------------------------------------------------------------------
    // Functions
    // -------------------------------------------------------------------------

    /// @notice Register a new multi-leg trade for settlement tracking
    /// @dev Reverts `UnresolvedTrade` while the caller holds a trade past expiry with a recorded
    ///      leg that was neither finalized nor abandoned, and `OpenTradeLimit` when the caller
    ///      already holds the maximum number of open trades.
    /// @param tradeRef Caller-chosen reference, unique per caller
    /// @param jurisdictionId Jurisdiction for compliance verification
    /// @param subTradeCount Number of sub-trades (must be in [2, 16], the pattern circuit's capacity)
    /// @return tradeId `computeTradeId(msg.sender, tradeRef)`, the key for every other call
    function registerTrade(bytes32 tradeRef, uint8 jurisdictionId, uint8 subTradeCount)
        external
        returns (bytes32 tradeId);

    /// @notice Trade key for a subject's reference: `keccak256(abi.encode(subject, tradeRef))`
    function computeTradeId(address subject, bytes32 tradeRef) external pure returns (bytes32 tradeId);

    /// @notice Record a sub-settlement by linking it to a verified compliance proof
    /// @dev Attestation: compliance variant for the trade's subject and jurisdiction,
    ///      `block.timestamp <= expiresAt`, `timestamp >= createdAt`, never used by any leg.
    /// @param tradeId The trade to record against
    /// @param index The sub-trade index (0-based, must be < subTradeCount)
    /// @param proofHash The proof hash from a prior oracle submission
    function recordSubSettlement(bytes32 tradeId, uint8 index, bytes32 proofHash) external;

    /// @notice Finalize a trade after all sub-settlements are recorded
    /// @dev Requires a pattern detection proof of analysis_type=STRUCTURING for the subject.
    ///      The caller supplies the original public inputs so the registry can verify
    ///      keccak256(patternPublicInputs) matches the attestation's stored publicInputsHash,
    ///      then enforces analysis_type==1 (anti-structuring). VELOCITY/ROUND-AMOUNT proofs
    ///      are rejected. The proof's `timestamp` public input must be >= the block time of the
    ///      last recorded leg (`PatternProofPredatesLastLeg`); the attestation's submission
    ///      time is not enough.
    /// @param tradeId The trade to finalize
    /// @param patternProofHash Proof hash of a pattern detection proof for the subject
    /// @param patternPublicInputs Original public inputs used to generate the pattern proof
    function finalizeTrade(bytes32 tradeId, bytes32 patternProofHash, bytes calldata patternPublicInputs) external;

    /// @notice Close an unfinalized trade, before or after expiry (for example after a leg
    ///         failed at its venue)
    /// @dev Subject only. With at least one leg recorded, requires a STRUCTURING pattern
    ///      proof checked exactly as in `finalizeTrade` but bound to the recorded legs
    ///      (`computeSettlementRoot`, unrecorded indices hash as zero). With no leg recorded
    ///      the proof arguments are ignored. Frees the trade's open slot.
    /// @param tradeId The trade to abandon
    /// @param patternProofHash Proof hash of a STRUCTURING pattern proof for the subject
    /// @param patternPublicInputs Original public inputs used to generate the pattern proof
    function abandonTrade(bytes32 tradeId, bytes32 patternProofHash, bytes calldata patternPublicInputs) external;

    /// @notice Expire a trade that has passed its expiry window without finalization
    /// @dev Permissionless after expiry. Sets `expired`, never `finalized`.
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
