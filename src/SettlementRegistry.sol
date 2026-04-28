// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {ISettlementRegistry} from "./interfaces/ISettlementRegistry.sol";
import {IXochiZKPOracle} from "./interfaces/IXochiZKPOracle.sol";
import {ProofTypes} from "./libraries/ProofTypes.sol";

/// @dev Mirror of XochiZKPOracle.PATTERN_STRUCTURING constant. Must match circuits/pattern.
uint256 constant PATTERN_STRUCTURING = 1;

/// @title SettlementRegistry -- Links sub-settlement compliance proofs to a trade identifier
/// @notice Immutable contract (no owner, no pause) that tracks multi-leg trade settlements.
///         Each sub-trade must reference a verified compliance attestation in the Xochi ZKP Oracle.
///         Anti-structuring: finalization requires a pattern detection proof for the subject.
contract SettlementRegistry is ISettlementRegistry {
    error ZeroAddress();

    /// @notice The oracle contract used for attestation lookups
    IXochiZKPOracle public immutable override oracle;

    /// @notice Trade expiry duration (7 days from registration)
    uint256 internal constant TRADE_TTL = 7 days;

    /// @notice Minimum number of sub-trades per settlement
    uint8 internal constant MIN_SUB_TRADES = 2;

    /// @notice Maximum number of sub-trades per settlement
    uint8 internal constant MAX_SUB_TRADES = 100;

    /// @notice Settlement storage by tradeId
    mapping(bytes32 tradeId => Settlement settlement) internal _settlements;

    /// @notice Sub-settlement storage by tradeId and index
    /// @dev tradeId => index => SubSettlement
    mapping(bytes32 tradeId => mapping(uint8 index => SubSettlement subSettlement)) internal _subSettlements;

    /// @param oracle_ The XochiZKPOracle contract address
    constructor(address oracle_) {
        if (oracle_ == address(0)) revert ZeroAddress();
        oracle = IXochiZKPOracle(oracle_);
    }

    // -------------------------------------------------------------------------
    // Core
    // -------------------------------------------------------------------------

    /// @inheritdoc ISettlementRegistry
    function registerTrade(bytes32 tradeId, uint8 jurisdictionId, uint8 subTradeCount) external {
        if (_settlements[tradeId].createdAt != 0) revert TradeAlreadyExists(tradeId);
        if (subTradeCount < MIN_SUB_TRADES || subTradeCount > MAX_SUB_TRADES) {
            revert InvalidSubTradeCount(subTradeCount);
        }

        _settlements[tradeId] = Settlement({
            tradeId: tradeId,
            subject: msg.sender,
            jurisdictionId: jurisdictionId,
            subTradeCount: subTradeCount,
            settledCount: 0,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + TRADE_TTL,
            finalized: false
        });

        emit TradeRegistered(tradeId, msg.sender, jurisdictionId, subTradeCount);
    }

    /// @inheritdoc ISettlementRegistry
    function recordSubSettlement(bytes32 tradeId, uint8 index, bytes32 proofHash) external {
        Settlement storage settlement = _settlements[tradeId];
        if (settlement.createdAt == 0) revert TradeNotFound(tradeId);
        if (msg.sender != settlement.subject) revert NotTradeSubject(msg.sender, settlement.subject);
        if (settlement.finalized) revert TradeAlreadyFinalized(tradeId);
        if (block.timestamp > settlement.expiresAt) revert TradeExpiredError(tradeId);
        if (index >= settlement.subTradeCount) revert SubTradeIndexOutOfBounds(index, settlement.subTradeCount);
        if (_subSettlements[tradeId][index].settledAt != 0) revert SubTradeAlreadySettled(tradeId, index);

        // Verify the attestation exists in the oracle
        IXochiZKPOracle.ComplianceAttestation memory attestation = _fetchAttestation(proofHash);

        // Verify attestation binds to the same subject and jurisdiction
        if (attestation.subject != settlement.subject) {
            revert SubjectMismatch(settlement.subject, attestation.subject);
        }
        if (attestation.jurisdictionId != settlement.jurisdictionId) {
            revert JurisdictionMismatch(settlement.jurisdictionId, attestation.jurisdictionId);
        }

        _subSettlements[tradeId][index] =
            SubSettlement({index: index, proofHash: proofHash, settledAt: block.timestamp});

        settlement.settledCount++;

        emit SubSettlementRecorded(tradeId, index, proofHash);
    }

    /// @inheritdoc ISettlementRegistry
    function finalizeTrade(bytes32 tradeId, bytes32 patternProofHash, bytes calldata patternPublicInputs) external {
        Settlement storage settlement = _settlements[tradeId];
        if (settlement.createdAt == 0) revert TradeNotFound(tradeId);
        if (msg.sender != settlement.subject) revert NotTradeSubject(msg.sender, settlement.subject);
        if (settlement.finalized) revert TradeAlreadyFinalized(tradeId);
        if (block.timestamp > settlement.expiresAt) revert TradeExpiredError(tradeId);
        if (settlement.settledCount != settlement.subTradeCount) {
            revert TradeNotComplete(tradeId, settlement.settledCount, settlement.subTradeCount);
        }

        // Anti-structuring: verify a pattern detection proof (0x03) exists for the subject.
        // Checks:
        //   1. patternProofHash is not zero
        //   2. The proof type is PATTERN (0x03) via oracle.getProofType()
        //   3. The attestation exists and subject matches
        //   4. The attestation was created after trade registration
        //   5. Caller-supplied patternPublicInputs hashes to the stored publicInputsHash
        //   6. analysis_type == STRUCTURING (1) -- VELOCITY / ROUND_AMOUNT proofs do NOT
        //      satisfy the anti-structuring guarantee that this registry depends on
        //
        // Jurisdiction is intentionally not checked. PATTERN proofs are jurisdiction-agnostic:
        // they analyze transaction patterns, not jurisdiction-specific thresholds.
        if (patternProofHash == bytes32(0)) revert PatternProofRequired(tradeId);
        uint8 proofType = oracle.getProofType(patternProofHash);
        if (proofType != ProofTypes.PATTERN) revert PatternProofRequired(tradeId);
        IXochiZKPOracle.ComplianceAttestation memory patternAttestation = _fetchAttestation(patternProofHash);
        if (patternAttestation.subject != settlement.subject) {
            revert SubjectMismatch(settlement.subject, patternAttestation.subject);
        }
        if (patternAttestation.timestamp < settlement.createdAt) revert PatternProofRequired(tradeId);

        bytes32 inputsHash = keccak256(patternPublicInputs);
        if (inputsHash != patternAttestation.publicInputsHash) {
            revert PatternPublicInputsMismatch(patternAttestation.publicInputsHash, inputsHash);
        }
        // PATTERN public inputs layout: [0]=analysis_type, [1]=result, ...
        // Length is enforced by the Oracle on submission (32 bytes * 6 fields).
        uint256 analysisType = uint256(bytes32(patternPublicInputs[0:32]));
        if (analysisType != PATTERN_STRUCTURING) {
            revert PatternAnalysisTypeMismatch(PATTERN_STRUCTURING, analysisType);
        }

        settlement.finalized = true;

        emit TradeFinalized(tradeId, block.timestamp);
    }

    /// @inheritdoc ISettlementRegistry
    function expireTrade(bytes32 tradeId) external {
        Settlement storage settlement = _settlements[tradeId];
        if (settlement.createdAt == 0) revert TradeNotFound(tradeId);
        if (settlement.finalized) revert TradeAlreadyFinalized(tradeId);
        if (block.timestamp <= settlement.expiresAt) revert TradeNotExpired(tradeId);

        settlement.finalized = true;

        emit TradeExpired(tradeId, block.timestamp);
    }

    // -------------------------------------------------------------------------
    // Views
    // -------------------------------------------------------------------------

    /// @inheritdoc ISettlementRegistry
    function getSettlement(bytes32 tradeId) external view returns (Settlement memory settlement) {
        settlement = _settlements[tradeId];
        if (settlement.createdAt == 0) revert TradeNotFound(tradeId);
    }

    /// @inheritdoc ISettlementRegistry
    function getSubSettlements(bytes32 tradeId) external view returns (SubSettlement[] memory subSettlements) {
        Settlement storage settlement = _settlements[tradeId];
        if (settlement.createdAt == 0) revert TradeNotFound(tradeId);

        // Count recorded sub-settlements
        uint256 count;
        for (uint8 i; i < settlement.subTradeCount;) {
            if (_subSettlements[tradeId][i].settledAt != 0) {
                unchecked {
                    ++count;
                }
            }
            unchecked {
                ++i;
            }
        }

        // Build result array
        subSettlements = new SubSettlement[](count);
        uint256 idx;
        for (uint8 i; i < settlement.subTradeCount;) {
            if (_subSettlements[tradeId][i].settledAt != 0) {
                subSettlements[idx] = _subSettlements[tradeId][i];
                unchecked {
                    ++idx;
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    /// @dev Fetch an attestation from the oracle, reverting if not found
    function _fetchAttestation(bytes32 proofHash)
        internal
        view
        returns (IXochiZKPOracle.ComplianceAttestation memory attestation)
    {
        try oracle.getHistoricalProof(proofHash) returns (IXochiZKPOracle.ComplianceAttestation memory att) {
            attestation = att;
        } catch {
            revert AttestationNotFound(proofHash);
        }
    }
}
