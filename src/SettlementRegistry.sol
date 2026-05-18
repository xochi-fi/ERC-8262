// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {ISettlementRegistry} from "./interfaces/ISettlementRegistry.sol";
import {IERC8262Oracle} from "./interfaces/IERC8262Oracle.sol";
import {ProofTypes} from "./libraries/ProofTypes.sol";

/// @dev Mirror of ERC8262Oracle.PATTERN_STRUCTURING constant. Must match circuits/pattern.
uint256 constant PATTERN_STRUCTURING = 1;

/// @title SettlementRegistry -- Links sub-settlement compliance proofs to a trade identifier
/// @notice Immutable contract (no owner, no pause) that tracks multi-leg trade settlements.
///         Each sub-trade must reference a verified compliance attestation in the ERC-8262 Oracle.
///         Anti-structuring: finalization requires a pattern detection proof for the subject.
contract SettlementRegistry is ISettlementRegistry {
    error ZeroAddress();

    /// @notice The oracle contract used for attestation lookups
    IERC8262Oracle public immutable override oracle;

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

    /// @notice Audit H-1: marks each pattern proof hash as consumed when used to
    ///         finalize a trade. Prevents a single PATTERN attestation from
    ///         finalizing more than one settlement.
    mapping(bytes32 patternProofHash => bool used) internal _usedPatternProofs;

    /// @notice BN254 scalar field modulus. Settlement_root public input is a Field
    ///         element; the keccak commitment must be reduced mod this so the
    ///         Solidity check matches the in-circuit representation.
    uint256 internal constant BN254_FR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @param oracle_ The ERC8262Oracle contract address
    constructor(address oracle_) {
        if (oracle_ == address(0)) revert ZeroAddress();
        oracle = IERC8262Oracle(oracle_);
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
        IERC8262Oracle.ComplianceAttestation memory attestation = _fetchAttestation(proofHash);

        // Reject any proof that is not a compliance variant. The interface
        // advertises "verified compliance attestation" semantics; MEMBERSHIP,
        // NON_MEMBERSHIP, RISK_SCORE(_SIGNED), PATTERN, and ATTESTATION proofs
        // for the same (subject, jurisdiction) would otherwise satisfy the
        // subject/jurisdiction checks below and silently substitute a non-AML
        // guarantee for the AML guarantee callers depend on.
        if (
            attestation.proofType != ProofTypes.COMPLIANCE && attestation.proofType != ProofTypes.COMPLIANCE_SIGNED
                && attestation.proofType != ProofTypes.COMPLIANCE_MULTI_SIGNED
        ) {
            revert NonComplianceProofType(proofHash, attestation.proofType);
        }

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
        //   7. The pattern proof's `settlement_root` public input matches the keccak
        //      commitment over this trade's recorded sub-settlement proof hashes
        //      (audit H-1; binds the pattern attestation to THIS specific settlement)
        //   8. The pattern proof has not been used to finalize a different trade
        //      (audit H-1 reuse-prevention; one PATTERN attestation per trade)
        //
        // Jurisdiction is intentionally not checked. PATTERN proofs are jurisdiction-agnostic:
        // they analyze transaction patterns, not jurisdiction-specific thresholds.
        if (patternProofHash == bytes32(0)) revert PatternProofRequired(tradeId);
        if (_usedPatternProofs[patternProofHash]) revert PatternProofAlreadyUsed(patternProofHash);
        uint8 proofType = oracle.getProofType(patternProofHash);
        if (proofType != ProofTypes.PATTERN) revert PatternProofRequired(tradeId);
        IERC8262Oracle.ComplianceAttestation memory patternAttestation = _fetchAttestation(patternProofHash);
        if (patternAttestation.subject != settlement.subject) {
            revert SubjectMismatch(settlement.subject, patternAttestation.subject);
        }
        if (patternAttestation.timestamp < settlement.createdAt) revert PatternProofRequired(tradeId);

        bytes32 inputsHash = keccak256(patternPublicInputs);
        if (inputsHash != patternAttestation.publicInputsHash) {
            revert PatternPublicInputsMismatch(patternAttestation.publicInputsHash, inputsHash);
        }
        // PATTERN public inputs layout (32 bytes each, 7 fields total after audit H-1):
        //   [0]=analysis_type, [1]=result, [2]=reporting_threshold, [3]=time_window,
        //   [4]=tx_set_hash, [5]=submitter, [6]=settlement_root
        // Length is enforced by the Oracle on submission.
        uint256 analysisType = uint256(bytes32(patternPublicInputs[0:32]));
        if (analysisType != PATTERN_STRUCTURING) {
            revert PatternAnalysisTypeMismatch(PATTERN_STRUCTURING, analysisType);
        }

        bytes32 expectedSettlementRoot = _computeSettlementRoot(tradeId, settlement.subTradeCount);
        bytes32 patternSettlementRoot = bytes32(patternPublicInputs[192:224]);
        if (patternSettlementRoot != expectedSettlementRoot) {
            revert SettlementRootMismatch(expectedSettlementRoot, patternSettlementRoot);
        }

        _usedPatternProofs[patternProofHash] = true;
        settlement.finalized = true;

        emit TradeFinalized(tradeId, block.timestamp);
    }

    /// @notice Compute the `settlement_root` public input that a PATTERN proof
    ///         must commit to in order to bind to `tradeId`.
    /// @dev `bytes32(uint256(keccak256(abi.encode(subTradeCount, proofHashes))) % BN254_FR_MODULUS)`,
    ///      where `proofHashes[i] = _subSettlements[tradeId][i].proofHash` for
    ///      `i` in `[0, subTradeCount)`. The mod reduces the keccak digest into
    ///      the BN254 scalar field so the value matches the in-circuit `Field`
    ///      representation when interpreted as a public input. Provers MUST call
    ///      this view function (or replicate `abi.encode(uint8, bytes32[])` +
    ///      keccak256 + field reduction off-chain bit-for-bit) before generating
    ///      their pattern proof. Off-chain replication note: `abi.encode` of
    ///      `(uint8, bytes32[])` produces 32 (subTradeCount, padded) + 32 (array
    ///      offset = 0x40) + 32 (array length = subTradeCount) + 32 * N (elements)
    ///      = 96 + 32*N bytes -- NOT a simple `||` concatenation.
    ///      Audit H-1: this binding is declarative -- the circuit does not verify
    ///      that the analyzed transactions correspond to the sub-settlements'
    ///      underlying transactions. The compliance circuits do not expose
    ///      transaction-amount commitments; a fully cryptographic binding would
    ///      require a v2 compliance circuit. This declarative binding is strictly
    ///      better than the previous (no binding) state: a single pattern proof
    ///      can no longer finalize multiple trades, and the pattern proof has to
    ///      be generated with knowledge of the specific sub-settlement set.
    /// @param tradeId The trade whose settlement root to compute
    /// @return root The expected settlement_root value
    function computeSettlementRoot(bytes32 tradeId) external view returns (bytes32 root) {
        Settlement storage settlement = _settlements[tradeId];
        if (settlement.createdAt == 0) revert TradeNotFound(tradeId);
        return _computeSettlementRoot(tradeId, settlement.subTradeCount);
    }

    /// @notice Whether a pattern proof has already been consumed to finalize a trade.
    function isPatternProofUsed(bytes32 patternProofHash) external view returns (bool used) {
        return _usedPatternProofs[patternProofHash];
    }

    function _computeSettlementRoot(bytes32 tradeId, uint8 subTradeCount) internal view returns (bytes32 root) {
        bytes32[] memory hashes = new bytes32[](subTradeCount);
        for (uint8 i; i < subTradeCount;) {
            hashes[i] = _subSettlements[tradeId][i].proofHash;
            unchecked {
                ++i;
            }
        }
        uint256 reduced = uint256(keccak256(abi.encode(subTradeCount, hashes))) % BN254_FR_MODULUS;
        return bytes32(reduced);
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
        returns (IERC8262Oracle.ComplianceAttestation memory attestation)
    {
        try oracle.getHistoricalProof(proofHash) returns (IERC8262Oracle.ComplianceAttestation memory att) {
            attestation = att;
        } catch {
            revert AttestationNotFound(proofHash);
        }
    }
}
