// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IXochiZKPOracle} from "./interfaces/IXochiZKPOracle.sol";
import {IXochiZKPVerifier} from "./interfaces/IXochiZKPVerifier.sol";
import {IUltraVerifier} from "./interfaces/IUltraVerifier.sol";
import {ProofTypes} from "./libraries/ProofTypes.sol";
import {JurisdictionConfig} from "./libraries/JurisdictionConfig.sol";
import {AccessControl} from "./libraries/AccessControl.sol";
import {Pausable} from "./libraries/Pausable.sol";
import {EIP712Attestation} from "./libraries/EIP712Attestation.sol";

/// @title XochiZKPOracle -- Reference implementation of the Xochi ZKP compliance oracle
/// @notice Records compliance attestations backed by verified ZK proofs and supports
///         retroactive proof-of-innocence lookups
/// @dev Privileged actions are split across roles (see AccessControl):
///      - GUARDIAN: pause/unpause (global + per-proof-type), revokeConfig, denyProvider
///      - REGISTRAR: register/revoke merkle roots and reporting thresholds, set provider publishers
///      - CONFIG: updateProviderConfig, updateAttestationTTL, compactConfigHistory,
///        registerProviderConfigExpansion
///      - owner: grant/revoke roles, transfer ownership
contract XochiZKPOracle is IXochiZKPOracle, AccessControl, Pausable {
    /// @notice The verifier contract used to validate proofs
    IXochiZKPVerifier public immutable verifier;

    /// @notice Hash of the current provider weight configuration
    bytes32 internal _providerConfigHash;

    /// @notice Duration in seconds that attestations remain valid (default: 24 hours)
    uint256 internal _attestationTTL;

    /// @notice Latest attestation per subject per jurisdiction
    /// @dev subject => jurisdictionId => attestation
    mapping(address subject => mapping(uint8 jurisdictionId => ComplianceAttestation attestation)) internal
        _attestations;

    /// @notice Attestation lookup by proof hash (for retroactive verification)
    mapping(bytes32 proofHash => ComplianceAttestation attestation) internal _proofIndex;

    /// @notice History of proof hashes per subject per jurisdiction
    /// @dev subject => jurisdictionId => proofHash[]
    mapping(address subject => mapping(uint8 jurisdictionId => bytes32[] proofHashes)) internal _attestationHistory;

    /// @notice Historical provider config hashes (versioned)
    bytes32[] internal _configHistory;

    /// @notice Track used proof hashes to prevent replay
    mapping(bytes32 proofHash => bool used) internal _usedProofs;

    /// @notice Proof type per proof hash (for downstream proof-type verification)
    mapping(bytes32 proofHash => uint8 proofType) internal _proofTypes;

    /// @notice Set of all valid (current + historical) provider config hashes
    mapping(bytes32 configHash => bool valid) internal _validConfigs;

    /// @notice Permanently-revoked provider config hashes; cannot be re-registered
    mapping(bytes32 configHash => bool revoked) internal _revokedConfigs;

    /// @notice Set of valid merkle roots for MEMBERSHIP/NON_MEMBERSHIP/ATTESTATION proofs
    mapping(bytes32 merkleRoot => bool valid) internal _validMerkleRoots;

    /// @notice Registered reporting thresholds for PATTERN proofs (anti-structuring)
    /// @dev Maps threshold value (as bytes32) to validity. Prevents jurisdiction spoofing
    ///      by ensuring the reporting_threshold in a PATTERN proof matches a registered value.
    mapping(bytes32 threshold => bool valid) internal _validReportingThresholds;

    /// @notice Per-proof-type pause state for surgical incident response
    mapping(uint8 proofType => bool isPaused) internal _proofTypePaused;

    /// @notice Per-provider authorized publisher EOA for ATTESTATION credential roots
    mapping(uint256 providerId => address publisher) internal _providerPublisher;

    /// @notice Per-config provider expansion: which provider IDs are members of a config hash.
    /// @dev Registered alongside `updateProviderConfig` via `registerProviderConfigExpansion`.
    ///      Used by `denyProvider` to invalidate every config containing a compromised provider
    ///      without rotating the underlying hash. The expansion is trust-on-publish: the
    ///      Oracle cannot recompute the Pedersen-based providerSetHash on-chain, so the
    ///      registrar is responsible for ensuring the expansion matches the off-chain config.
    ///      Mismatches do not affect proof acceptance unless `denyProvider` is invoked --
    ///      which only the GUARDIAN can do.
    mapping(bytes32 configHash => uint256[] providerIds) internal _configProviders;

    /// @notice Provider IDs marked as compromised. Configs that include any denied provider
    ///         are rejected at compliance proof submission time.
    mapping(uint256 providerId => bool denied) internal _deniedProviders;

    /// @notice Highest proof-internal timestamp recorded per (subject, jurisdiction).
    /// @dev Per-subject ratchet that prevents an old proof from overwriting a newer attestation.
    ///      The stored value is the proof's `timestamp` public input (or `block.timestamp` for
    ///      proof types without an internal timestamp -- RISK_SCORE and PATTERN). New proofs
    ///      must be non-decreasing (>= last); equal timestamps are allowed so legitimate
    ///      same-block submissions of different proof types can coexist for the same pair.
    mapping(address subject => mapping(uint8 jurisdictionId => uint256 lastProofTimestamp)) internal
        _lastProofTimestamp;

    /// @notice Metadata for a published credential tree root
    struct CredentialRootInfo {
        uint256 providerId;
        uint64 registeredAt;
        bool revoked;
    }

    /// @notice Published credential roots with provenance + TTL window
    mapping(bytes32 root => CredentialRootInfo info) internal _credentialRoots;

    error ProofVerificationFailed();
    error ProofAlreadyUsed(bytes32 proofHash);
    error InvalidTTL();
    error AttestationNotFound(bytes32 proofHash);
    error PublicInputMismatch();
    error InvalidConfigHash(bytes32 configHash);
    error InvalidMerkleRoot(bytes32 merkleRoot);
    error InvalidReportingThreshold(bytes32 threshold);
    error CannotRevokeCurrentConfig();
    error ProofResultNegative();
    error SubmitterMismatch();
    error ConfigHistoryFull();
    error ConfigAlreadyCurrent();
    error AlreadyRegistered();
    error NotRegistered();
    error BatchLengthMismatch();
    error EmptyBatch();
    error BatchTooLarge();
    error TimeWindowTooSmall(uint256 timeWindow, uint256 minimum);
    error ProofTimestampStale(uint256 proofTimestamp, uint256 blockTimestamp);
    error ProofTypePaused(uint8 proofType);
    error ProofTypeNotPaused(uint8 proofType);
    error InvalidRiskProofType(uint256 proofType);
    error InvalidRiskDirection(uint256 direction);
    error TrivialRiskBound(uint256 boundLower, uint256 boundUpper);
    error InvalidRiskBound(uint256 boundLower, uint256 boundUpper);
    error InvalidAnalysisType(uint256 analysisType);
    error ConfigPermanentlyRevoked(bytes32 configHash);
    error NotProviderPublisher(uint256 providerId, address caller);
    error CredentialRootAlreadyPublished(bytes32 root);
    error CredentialRootNotFound(bytes32 root);
    error InvalidProviderId();
    error CredentialRootExpired(bytes32 root, uint256 registeredAt);
    error CredentialRootProviderMismatch(uint256 expected, uint256 actual);
    error ConfigExpansionAlreadySet(bytes32 configHash);
    error ConfigExpansionNotRegistered(bytes32 configHash);
    error ProviderDenied(uint256 providerId);
    error EmptyProviderExpansion();
    error ProofTimestampNotMonotonic(uint256 proofTimestamp, uint256 lastTimestamp);

    event ConfigHistoryCompacted(uint256 entriesRemoved, uint256 newLength);
    event ProviderPublisherSet(uint256 indexed providerId, address indexed previous, address indexed publisher);
    event CredentialRootPublished(uint256 indexed providerId, bytes32 indexed root, string cid, uint256 registeredAt);
    event CredentialRootRevoked(bytes32 indexed root);
    event ProviderConfigExpansionRegistered(bytes32 indexed configHash, uint256[] providerIds);
    event ProviderDeniedEvent(uint256 indexed providerId);
    event ProviderUndeniedEvent(uint256 indexed providerId);

    /// @notice Maximum number of entries in the config history array
    uint256 public constant MAX_CONFIG_HISTORY = 256;

    /// @notice Maximum number of proofs in a single batch submission
    uint256 public constant MAX_BATCH_SIZE = 100;

    /// @notice Minimum time window for PATTERN (anti-structuring) proofs in seconds
    uint256 public constant MIN_TIME_WINDOW = 3600;

    /// @notice Maximum age of a proof timestamp relative to block.timestamp
    uint256 public constant MAX_PROOF_AGE = 1 hours;

    /// @notice Maximum risk score in basis points (matches risk_score circuit semantics)
    uint256 public constant MAX_RISK_SCORE_BPS = 10000;

    /// @notice Risk score proof_type identifiers (must match circuits/risk_score)
    uint8 internal constant RISK_PROOF_THRESHOLD = 0x01;
    uint8 internal constant RISK_PROOF_RANGE = 0x02;

    /// @notice Risk score direction identifiers (must match circuits/risk_score)
    uint8 internal constant RISK_DIRECTION_GT = 1;
    uint8 internal constant RISK_DIRECTION_LT = 2;

    /// @notice Pattern analysis identifiers (must match circuits/pattern)
    uint8 public constant PATTERN_STRUCTURING = 1;
    uint8 public constant PATTERN_VELOCITY = 2;
    uint8 public constant PATTERN_ROUND_AMOUNT = 3;

    /// @notice Lifetime of a published credential root before it auto-expires
    /// @dev Providers are expected to publish new roots more frequently than this; the
    ///      window allows a grace period during which old paths against an outgoing root
    ///      remain provable. After expiry, users must obtain paths against a current root.
    uint256 public constant CREDENTIAL_ROOT_TTL = 48 hours;

    /// @param _verifier The XochiZKPVerifier contract address
    /// @param initialOwner The initial owner address
    /// @param initialConfigHash The initial provider weight configuration hash
    constructor(address _verifier, address initialOwner, bytes32 initialConfigHash) {
        if (_verifier == address(0) || initialOwner == address(0)) revert ZeroAddress();
        if (initialConfigHash == bytes32(0)) revert InvalidConfigHash(bytes32(0));

        verifier = IXochiZKPVerifier(_verifier);
        owner = initialOwner;
        _providerConfigHash = initialConfigHash;
        _attestationTTL = 24 hours;

        _configHistory.push(initialConfigHash);
        _validConfigs[initialConfigHash] = true;

        emit OwnershipTransferred(address(0), initialOwner);
        emit ProviderWeightsUpdated(initialConfigHash, block.timestamp, "");
    }

    // -------------------------------------------------------------------------
    // IXochiZKPOracle -- Core
    // -------------------------------------------------------------------------

    /// @inheritdoc IXochiZKPOracle
    function submitCompliance(
        uint8 jurisdictionId,
        uint8 proofType,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 providerSetHash
    ) external whenNotPaused returns (ComplianceAttestation memory attestation) {
        if (_proofTypePaused[proofType]) revert ProofTypePaused(proofType);
        JurisdictionConfig.validateJurisdiction(jurisdictionId);

        // Validate that caller-supplied parameters match what's in the proof's public inputs.
        // This prevents submitting a proof generated for one context in a different context.
        // Each validator returns the timestamp to ratchet on -- proof-internal for types that
        // expose one, block.timestamp otherwise.
        uint256 proofTimestamp = _validateAndExtractTimestamp(jurisdictionId, proofType, providerSetHash, publicInputs);
        _ratchet(jurisdictionId, proofTimestamp);

        // Verify proof and check replay (extracted to reduce stack depth)
        (address verifierUsed, bytes32 proofHash) = _verifyAndRecordProof(proofType, proof, publicInputs);

        // Build and store attestation (providerSetHash only meaningful for COMPLIANCE proofs)
        bytes32 effectiveProviderSetHash = proofType == ProofTypes.COMPLIANCE ? providerSetHash : bytes32(0);
        attestation = _buildAttestation(
            jurisdictionId, proofType, proofHash, effectiveProviderSetHash, keccak256(publicInputs), verifierUsed
        );

        uint256 previousExpiresAt = _attestations[msg.sender][jurisdictionId].expiresAt;
        _attestations[msg.sender][jurisdictionId] = attestation;
        _proofIndex[proofHash] = attestation;
        _proofTypes[proofHash] = proofType;
        _attestationHistory[msg.sender][jurisdictionId].push(proofHash);

        emit ComplianceVerified(msg.sender, jurisdictionId, true, proofHash, attestation.expiresAt, previousExpiresAt);
    }

    /// @inheritdoc IXochiZKPOracle
    function submitComplianceBatch(
        uint8 jurisdictionId,
        uint8[] calldata proofTypes,
        bytes[] calldata proofs,
        bytes[] calldata publicInputs,
        bytes32[] calldata providerSetHashes
    ) external whenNotPaused returns (ComplianceAttestation[] memory attestations) {
        uint256 length = proofTypes.length;
        if (length == 0) revert EmptyBatch();
        if (length > MAX_BATCH_SIZE) revert BatchTooLarge();
        if (length != proofs.length || length != publicInputs.length || length != providerSetHashes.length) {
            revert BatchLengthMismatch();
        }

        JurisdictionConfig.validateJurisdiction(jurisdictionId);

        attestations = new ComplianceAttestation[](length);

        for (uint256 i; i < length;) {
            attestations[i] =
                _submitSingle(jurisdictionId, proofTypes[i], proofs[i], publicInputs[i], providerSetHashes[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IXochiZKPOracle
    function checkCompliance(address subject, uint8 jurisdictionId)
        external
        view
        returns (bool valid, ComplianceAttestation memory attestation)
    {
        attestation = _attestations[subject][jurisdictionId];

        // Valid if attestation exists, threshold was met, and not expired
        valid = attestation.timestamp > 0 && attestation.meetsThreshold && block.timestamp <= attestation.expiresAt;
    }

    /// @inheritdoc IXochiZKPOracle
    function checkComplianceByType(address subject, uint8 jurisdictionId, uint8 proofType)
        external
        view
        returns (bool valid, ComplianceAttestation memory attestation)
    {
        attestation = _attestations[subject][jurisdictionId];
        valid = attestation.timestamp > 0 && attestation.meetsThreshold && block.timestamp <= attestation.expiresAt
            && attestation.proofType == proofType;
    }

    /// @inheritdoc IXochiZKPOracle
    function getHistoricalProof(bytes32 proofHash) external view returns (ComplianceAttestation memory attestation) {
        attestation = _proofIndex[proofHash];
        if (attestation.timestamp == 0) revert AttestationNotFound(proofHash);
    }

    /// @inheritdoc IXochiZKPOracle
    function getProofType(bytes32 proofHash) external view returns (uint8) {
        if (_proofIndex[proofHash].timestamp == 0) revert AttestationNotFound(proofHash);
        return _proofTypes[proofHash];
    }

    /// @inheritdoc IXochiZKPOracle
    /// @dev WARNING: Returns an unbounded array. Gas cost scales linearly with the
    ///      number of attestations for the given (subject, jurisdictionId) pair.
    ///      A subject could self-attest many times (each with a unique proof), growing
    ///      the array until this view exceeds block gas limits or RPC response size.
    ///      This does NOT affect other users (submitter pays their own gas), but can
    ///      make this view unusable for the affected subject.
    ///      For production integrations, use getAttestationHistoryPaginated() which
    ///      supports offset/limit pagination and is safe regardless of history size.
    function getAttestationHistory(address subject, uint8 jurisdictionId)
        external
        view
        returns (bytes32[] memory proofHashes)
    {
        return _attestationHistory[subject][jurisdictionId];
    }

    /// @notice Get a paginated slice of attestation history
    /// @param subject The address to query
    /// @param jurisdictionId The jurisdiction
    /// @param offset Starting index
    /// @param limit Maximum number of entries to return
    /// @return proofHashes The proof hashes in the requested range
    /// @return total Total number of attestations for pagination
    function getAttestationHistoryPaginated(address subject, uint8 jurisdictionId, uint256 offset, uint256 limit)
        external
        view
        returns (bytes32[] memory proofHashes, uint256 total)
    {
        bytes32[] storage history = _attestationHistory[subject][jurisdictionId];
        total = history.length;

        if (offset >= total) {
            return (new bytes32[](0), total);
        }

        uint256 end = offset + limit;
        if (end > total) end = total;
        uint256 count = end - offset;

        proofHashes = new bytes32[](count);
        for (uint256 i; i < count;) {
            proofHashes[i] = history[offset + i];
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IXochiZKPOracle
    function providerConfigHash() external view returns (bytes32 configHash) {
        return _providerConfigHash;
    }

    /// @inheritdoc IXochiZKPOracle
    function attestationTTL() external view returns (uint256 ttl) {
        return _attestationTTL;
    }

    /// @notice EIP-712 domain separator for this oracle instance
    /// @dev Computed at call time using block.chainid (fork-safe, not cached)
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return EIP712Attestation.buildDomainSeparator(address(this));
    }

    /// @notice Compute the proofHash that this Oracle will derive for a given (proof, proofType).
    /// @dev Pure helper exposing the hashing scheme: keccak256(proof, proofType, chainId, oracle).
    ///      Off-chain integrators and tests should use this to derive expected proofHash values
    ///      rather than recomputing the encoding manually -- this function is the source of truth.
    function computeProofHash(bytes calldata proof, uint8 proofType) external view returns (bytes32) {
        return keccak256(abi.encodePacked(proof, proofType, block.chainid, address(this)));
    }

    /// @notice EIP-712 struct hash of a ComplianceAttestation
    /// @param att The attestation to hash
    /// @return structHash The EIP-712 struct hash
    function hashAttestation(ComplianceAttestation memory att) external pure returns (bytes32) {
        return EIP712Attestation.hashAttestation(att);
    }

    // -------------------------------------------------------------------------
    // Admin
    // -------------------------------------------------------------------------

    /// @notice Update the provider weight configuration
    /// @dev A previously-revoked config hash cannot be re-registered. Mistaken revocations
    ///      require deploying a fresh hash (hash of new metadata), not re-using the old one.
    /// @param newConfigHash The new configuration hash
    /// @param metadataURI URI pointing to the full config (IPFS, Arweave, etc.)
    function updateProviderConfig(bytes32 newConfigHash, string calldata metadataURI) external onlyRole(CONFIG_ROLE) {
        if (newConfigHash == _providerConfigHash) revert ConfigAlreadyCurrent();
        if (_revokedConfigs[newConfigHash]) revert ConfigPermanentlyRevoked(newConfigHash);
        if (_configHistory.length >= MAX_CONFIG_HISTORY) revert ConfigHistoryFull();
        _providerConfigHash = newConfigHash;
        _configHistory.push(newConfigHash);
        _validConfigs[newConfigHash] = true;
        emit ProviderWeightsUpdated(newConfigHash, block.timestamp, metadataURI);
    }

    /// @notice Update the attestation TTL
    /// @param newTTL The new TTL in seconds (minimum 1 hour, maximum 30 days)
    function updateAttestationTTL(uint256 newTTL) external onlyRole(CONFIG_ROLE) {
        if (newTTL < 1 hours || newTTL > 30 days) revert InvalidTTL();
        uint256 oldTTL = _attestationTTL;
        _attestationTTL = newTTL;
        emit AttestationTTLUpdated(oldTTL, newTTL);
    }

    /// @notice Get the number of historical provider config versions
    /// @return count Number of config versions
    function configHistoryLength() external view returns (uint256 count) {
        return _configHistory.length;
    }

    /// @notice Get a historical provider config hash by index
    /// @param index The version index (0 = initial)
    /// @return configHash The config hash at that version
    function configHistoryAt(uint256 index) external view returns (bytes32 configHash) {
        return _configHistory[index];
    }

    /// @notice Revoke a provider config hash so proofs using it are no longer accepted
    /// @dev Revocation is permanent. Once revoked, the same hash cannot be re-registered
    ///      via `updateProviderConfig`; this prevents silently un-revoking by reuse.
    /// @param configHash The config hash to revoke (cannot be the current active config)
    function revokeConfig(bytes32 configHash) external onlyRole(GUARDIAN_ROLE) {
        if (configHash == _providerConfigHash) revert CannotRevokeCurrentConfig();
        _validConfigs[configHash] = false;
        _revokedConfigs[configHash] = true;
        emit ConfigRevoked(configHash);
    }

    /// @notice Check if a config hash has been permanently revoked
    /// @param configHash The config hash to check
    /// @return revoked Whether the config hash is in the revoked set
    function isRevokedConfig(bytes32 configHash) external view returns (bool revoked) {
        return _revokedConfigs[configHash];
    }

    /// @notice Remove revoked entries from config history to free slots
    /// @dev Preserves ordering of remaining entries. Current config (last entry) is
    ///      never revoked (CannotRevokeCurrentConfig guard), so it always survives.
    ///      Gas cost scales with history length (up to ~2.5M at 256 entries).
    /// @return removed Number of entries removed
    function compactConfigHistory() external onlyRole(CONFIG_ROLE) returns (uint256 removed) {
        uint256 len = _configHistory.length;
        uint256 writeIdx;

        for (uint256 readIdx; readIdx < len;) {
            bytes32 cfg = _configHistory[readIdx];
            if (_validConfigs[cfg]) {
                if (writeIdx != readIdx) {
                    _configHistory[writeIdx] = cfg;
                }
                unchecked {
                    ++writeIdx;
                }
            }
            unchecked {
                ++readIdx;
            }
        }

        removed = len - writeIdx;

        for (uint256 i; i < removed;) {
            _configHistory.pop();
            unchecked {
                ++i;
            }
        }

        if (removed > 0) {
            emit ConfigHistoryCompacted(removed, writeIdx);
        }
    }

    /// @notice Check if a config hash is valid (current or historical, not revoked)
    /// @param configHash The config hash to check
    /// @return valid Whether the config hash has been registered and not revoked
    function isValidConfig(bytes32 configHash) external view returns (bool valid) {
        return _validConfigs[configHash];
    }

    // -------------------------------------------------------------------------
    // Per-provider denylist (compliance proofs)
    // -------------------------------------------------------------------------

    /// @notice Register the provider expansion behind a registered config hash.
    /// @dev Required before `denyProvider` can take effect for compliance proofs that use
    ///      this config. The expansion is the list of provider IDs whose weights are
    ///      committed-to by `configHash`; the Oracle cannot recompute the Pedersen hash
    ///      on-chain, so the CONFIG role is trusted to publish the matching set.
    ///      Expansions are append-only (single-write) to prevent silently swapping the
    ///      provider list out from under previously-emitted proofs.
    /// @param configHash The previously-registered config hash (current or historical, not revoked)
    /// @param providerIds The full list of provider IDs that contributed to this config
    function registerProviderConfigExpansion(bytes32 configHash, uint256[] calldata providerIds)
        external
        onlyRole(CONFIG_ROLE)
    {
        if (!_validConfigs[configHash]) revert InvalidConfigHash(configHash);
        if (_configProviders[configHash].length != 0) revert ConfigExpansionAlreadySet(configHash);
        if (providerIds.length == 0) revert EmptyProviderExpansion();

        // Copy calldata into storage; reject zero IDs (matches `setProviderPublisher` invariant)
        uint256 length = providerIds.length;
        for (uint256 i; i < length;) {
            if (providerIds[i] == 0) revert InvalidProviderId();
            _configProviders[configHash].push(providerIds[i]);
            unchecked {
                ++i;
            }
        }

        emit ProviderConfigExpansionRegistered(configHash, providerIds);
    }

    /// @notice Mark a provider as denied. Compliance proofs whose config expansion includes
    ///         this provider are rejected at submission time.
    /// @dev Reversible via `undenyProvider`. Pair with `pauseProofType(COMPLIANCE)` for an
    ///      immediate freeze while owners coordinate the new config rotation.
    /// @param providerId The provider identifier (must be non-zero)
    function denyProvider(uint256 providerId) external onlyRole(GUARDIAN_ROLE) {
        if (providerId == 0) revert InvalidProviderId();
        if (_deniedProviders[providerId]) revert AlreadyRegistered();
        _deniedProviders[providerId] = true;
        emit ProviderDeniedEvent(providerId);
    }

    /// @notice Lift a previous denial. Mistaken denials should generally roll forward via a
    ///         config rotation rather than reuse, but this path exists for false-positive recovery.
    /// @param providerId The provider identifier
    function undenyProvider(uint256 providerId) external onlyRole(GUARDIAN_ROLE) {
        if (!_deniedProviders[providerId]) revert NotRegistered();
        _deniedProviders[providerId] = false;
        emit ProviderUndeniedEvent(providerId);
    }

    /// @notice Check whether a provider is currently denied.
    function isProviderDenied(uint256 providerId) external view returns (bool denied) {
        return _deniedProviders[providerId];
    }

    /// @notice Get the registered provider expansion for a config hash.
    /// @return providerIds The provider IDs registered for this config (empty array if unset)
    function getProviderConfigExpansion(bytes32 configHash) external view returns (uint256[] memory providerIds) {
        return _configProviders[configHash];
    }

    /// @dev True if the registered expansion for `configHash` contains any denied provider.
    ///      Returns false if no expansion has been registered (denial only enforces against
    ///      configs whose expansion is on-chain). Configs without an expansion still validate
    ///      via `_validConfigs`; per-provider denial is opt-in by registration.
    function _configContainsDeniedProvider(bytes32 configHash) internal view returns (bool) {
        uint256[] storage providers = _configProviders[configHash];
        uint256 length = providers.length;
        for (uint256 i; i < length;) {
            if (_deniedProviders[providers[i]]) return true;
            unchecked {
                ++i;
            }
        }
        return false;
    }

    /// @notice Register a merkle root as valid for MEMBERSHIP/NON_MEMBERSHIP/ATTESTATION proofs
    /// @param merkleRoot The merkle root to register
    function registerMerkleRoot(bytes32 merkleRoot) external onlyRole(REGISTRAR_ROLE) {
        if (_validMerkleRoots[merkleRoot]) revert AlreadyRegistered();
        _validMerkleRoots[merkleRoot] = true;
        emit MerkleRootRegistered(merkleRoot);
    }

    /// @notice Revoke a merkle root so proofs using it are no longer accepted
    /// @param merkleRoot The merkle root to revoke
    function revokeMerkleRoot(bytes32 merkleRoot) external onlyRole(REGISTRAR_ROLE) {
        if (!_validMerkleRoots[merkleRoot]) revert NotRegistered();
        _validMerkleRoots[merkleRoot] = false;
        emit MerkleRootRevoked(merkleRoot);
    }

    /// @notice Check if a merkle root is valid
    /// @param merkleRoot The merkle root to check
    /// @return valid Whether the merkle root has been registered and not revoked
    function isValidMerkleRoot(bytes32 merkleRoot) external view returns (bool valid) {
        return _validMerkleRoots[merkleRoot];
    }

    // -------------------------------------------------------------------------
    // Per-provider credential roots (ATTESTATION proofs)
    // -------------------------------------------------------------------------

    /// @notice Authorize an EOA to publish credential roots for a provider.
    /// @dev Initial set or rotation. Set publisher = address(0) to disable a provider.
    /// @param providerId Provider identifier (must be non-zero)
    /// @param publisher Address authorized to call publishCredentialRoot for this providerId
    function setProviderPublisher(uint256 providerId, address publisher) external onlyRole(REGISTRAR_ROLE) {
        if (providerId == 0) revert InvalidProviderId();
        address previous = _providerPublisher[providerId];
        _providerPublisher[providerId] = publisher;
        emit ProviderPublisherSet(providerId, previous, publisher);
    }

    /// @notice Publish a new credential tree root for a provider.
    /// @dev Called by the provider's authorized publisher EOA. Emits the IPFS CID for
    ///      the tree contents so users can fetch their merkle paths off-chain.
    /// @param providerId Provider identifier
    /// @param root New credential merkle root
    /// @param cid IPFS / Arweave CID for the full tree contents
    function publishCredentialRoot(uint256 providerId, bytes32 root, string calldata cid) external {
        address publisher = _providerPublisher[providerId];
        if (publisher == address(0) || msg.sender != publisher) {
            revert NotProviderPublisher(providerId, msg.sender);
        }
        if (_credentialRoots[root].registeredAt != 0) revert CredentialRootAlreadyPublished(root);

        _credentialRoots[root] =
            CredentialRootInfo({providerId: providerId, registeredAt: uint64(block.timestamp), revoked: false});
        emit CredentialRootPublished(providerId, root, cid, block.timestamp);
    }

    /// @notice Revoke a credential root before its TTL elapses.
    /// @dev Either the contract owner or the provider's publisher may revoke.
    /// @param root The credential root to revoke
    function revokeCredentialRoot(bytes32 root) external {
        CredentialRootInfo storage info = _credentialRoots[root];
        if (info.registeredAt == 0) revert CredentialRootNotFound(root);
        if (msg.sender != owner && msg.sender != _providerPublisher[info.providerId]) {
            revert NotProviderPublisher(info.providerId, msg.sender);
        }
        if (info.revoked) revert AlreadyRegistered(); // reuse: "already revoked"
        info.revoked = true;
        emit CredentialRootRevoked(root);
    }

    /// @notice Check whether a credential root is currently provable.
    /// @dev Valid iff registered, not revoked, and within the TTL window.
    function isValidCredentialRoot(bytes32 root) public view returns (bool) {
        return _isValidCredentialRoot(root);
    }

    /// @notice Get full metadata for a published credential root.
    function getCredentialRoot(bytes32 root) external view returns (CredentialRootInfo memory) {
        CredentialRootInfo memory info = _credentialRoots[root];
        if (info.registeredAt == 0) revert CredentialRootNotFound(root);
        return info;
    }

    /// @notice Get the publisher EOA authorized to publish for a provider.
    function getProviderPublisher(uint256 providerId) external view returns (address) {
        return _providerPublisher[providerId];
    }

    function _isValidCredentialRoot(bytes32 root) internal view returns (bool) {
        CredentialRootInfo memory info = _credentialRoots[root];
        if (info.registeredAt == 0) return false;
        if (info.revoked) return false;
        if (block.timestamp > uint256(info.registeredAt) + CREDENTIAL_ROOT_TTL) return false;
        return true;
    }

    /// @notice Register a reporting threshold for PATTERN (anti-structuring) proofs
    /// @param threshold The threshold value (as bytes32-encoded u64)
    function registerReportingThreshold(bytes32 threshold) external onlyRole(REGISTRAR_ROLE) {
        if (_validReportingThresholds[threshold]) revert AlreadyRegistered();
        _validReportingThresholds[threshold] = true;
        emit ReportingThresholdRegistered(threshold);
    }

    /// @notice Revoke a reporting threshold
    /// @param threshold The threshold to revoke
    function revokeReportingThreshold(bytes32 threshold) external onlyRole(REGISTRAR_ROLE) {
        if (!_validReportingThresholds[threshold]) revert NotRegistered();
        _validReportingThresholds[threshold] = false;
        emit ReportingThresholdRevoked(threshold);
    }

    /// @notice Check if a reporting threshold is valid
    /// @param threshold The threshold to check
    /// @return valid Whether the threshold has been registered and not revoked
    function isValidReportingThreshold(bytes32 threshold) external view returns (bool valid) {
        return _validReportingThresholds[threshold];
    }

    /// @notice Pause the contract, blocking all new submissions
    function pause() external override onlyRole(GUARDIAN_ROLE) {
        if (paused) revert ContractPaused();
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Unpause the contract, resuming all submissions
    function unpause() external override onlyRole(GUARDIAN_ROLE) {
        if (!paused) revert ContractNotPaused();
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @notice Pause submissions for a single proof type (surgical response)
    /// @param proofType The proof type to pause (0x01-0x06)
    function pauseProofType(uint8 proofType) external onlyRole(GUARDIAN_ROLE) {
        if (!ProofTypes.isValidProofType(proofType)) revert ProofTypes.InvalidProofType(proofType);
        if (_proofTypePaused[proofType]) revert ProofTypePaused(proofType);
        _proofTypePaused[proofType] = true;
        emit ProofTypePausedEvent(proofType, msg.sender);
    }

    /// @notice Unpause submissions for a single proof type
    /// @param proofType The proof type to unpause (0x01-0x06)
    function unpauseProofType(uint8 proofType) external onlyRole(GUARDIAN_ROLE) {
        if (!ProofTypes.isValidProofType(proofType)) revert ProofTypes.InvalidProofType(proofType);
        if (!_proofTypePaused[proofType]) revert ProofTypeNotPaused(proofType);
        _proofTypePaused[proofType] = false;
        emit ProofTypeUnpausedEvent(proofType, msg.sender);
    }

    /// @notice Check if a specific proof type is paused
    /// @param proofType The proof type to check
    /// @return Whether the proof type is paused
    function isProofTypePaused(uint8 proofType) external view returns (bool) {
        return _proofTypePaused[proofType];
    }

    event ProofTypePausedEvent(uint8 indexed proofType, address indexed account);
    event ProofTypeUnpausedEvent(uint8 indexed proofType, address indexed account);

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    /// @dev Process a single entry in a batch (or standalone) submission.
    ///      Extracted to avoid stack-too-deep in the batch loop.
    function _submitSingle(
        uint8 jurisdictionId,
        uint8 proofType,
        bytes calldata proof,
        bytes calldata inputs,
        bytes32 providerSetHash
    ) internal returns (ComplianceAttestation memory attestation) {
        if (_proofTypePaused[proofType]) revert ProofTypePaused(proofType);
        uint256 proofTimestamp = _validateAndExtractTimestamp(jurisdictionId, proofType, providerSetHash, inputs);
        _ratchet(jurisdictionId, proofTimestamp);

        (address verifierUsed, bytes32 proofHash) = _verifyAndRecordProof(proofType, proof, inputs);

        bytes32 effectiveProviderSetHash = proofType == ProofTypes.COMPLIANCE ? providerSetHash : bytes32(0);
        attestation = _buildAttestation(
            jurisdictionId, proofType, proofHash, effectiveProviderSetHash, keccak256(inputs), verifierUsed
        );

        uint256 previousExpiresAt = _attestations[msg.sender][jurisdictionId].expiresAt;
        _attestations[msg.sender][jurisdictionId] = attestation;
        _proofIndex[proofHash] = attestation;
        _proofTypes[proofHash] = proofType;
        _attestationHistory[msg.sender][jurisdictionId].push(proofHash);

        emit ComplianceVerified(msg.sender, jurisdictionId, true, proofHash, attestation.expiresAt, previousExpiresAt);
    }

    /// @dev Verify the ZK proof and record replay protection.
    ///      Resolves verifier address once to eliminate TOCTOU.
    function _verifyAndRecordProof(uint8 proofType, bytes calldata proof, bytes calldata publicInputs)
        internal
        returns (address verifierUsed, bytes32 proofHash)
    {
        verifierUsed = verifier.getVerifier(proofType);
        if (verifierUsed == address(0)) revert ProofVerificationFailed();
        ProofTypes.validatePublicInputs(proofType, publicInputs);
        bytes32[] memory inputs = ProofTypes.decodePublicInputs(publicInputs);
        bool valid = IUltraVerifier(verifierUsed).verify(proof, inputs);
        if (!valid) revert ProofVerificationFailed();

        // Key on (proof, proofType, chainId, oracleAddress) so identical proof bytes for
        // different types, chains, or oracle deployments don't collide. The chainid +
        // address(this) binding prevents cross-chain replay (same proof bytes submitted on
        // Optimism, Base, Arbitrum, etc.) and cross-deployment replay (same proof submitted
        // to a forked or alternate Oracle on the same chain).
        proofHash = keccak256(abi.encodePacked(proof, proofType, block.chainid, address(this)));
        if (_usedProofs[proofHash]) revert ProofAlreadyUsed(proofHash);
        _usedProofs[proofHash] = true;
    }

    /// @dev Build a ComplianceAttestation struct (extracted to reduce stack depth)
    function _buildAttestation(
        uint8 jurisdictionId,
        uint8 proofType,
        bytes32 proofHash,
        bytes32 providerSetHash,
        bytes32 publicInputsHash,
        address verifierUsed
    ) internal view returns (ComplianceAttestation memory attestation) {
        attestation = ComplianceAttestation({
            subject: msg.sender,
            jurisdictionId: jurisdictionId,
            proofType: proofType,
            meetsThreshold: true,
            timestamp: block.timestamp,
            expiresAt: block.timestamp + _attestationTTL,
            proofHash: proofHash,
            providerSetHash: providerSetHash,
            publicInputsHash: publicInputsHash,
            verifierUsed: verifierUsed
        });
    }

    /// @dev Dispatch validation by proofType and return the timestamp to ratchet on.
    function _validateAndExtractTimestamp(
        uint8 jurisdictionId,
        uint8 proofType,
        bytes32 providerSetHash,
        bytes calldata publicInputs
    ) internal view returns (uint256 proofTimestamp) {
        if (proofType == ProofTypes.COMPLIANCE) {
            return _validateComplianceInputs(jurisdictionId, providerSetHash, publicInputs);
        } else if (proofType == ProofTypes.RISK_SCORE) {
            return _validateRiskScoreInputs(publicInputs);
        } else if (proofType == ProofTypes.PATTERN) {
            return _validatePatternInputs(publicInputs);
        } else if (proofType == ProofTypes.ATTESTATION) {
            return _validateAttestationInputs(publicInputs);
        } else if (proofType == ProofTypes.MEMBERSHIP) {
            return _validateMembershipInputs(publicInputs);
        } else if (proofType == ProofTypes.NON_MEMBERSHIP) {
            return _validateNonMembershipInputs(publicInputs);
        } else {
            revert ProofTypes.InvalidProofType(proofType);
        }
    }

    /// @dev Per-(subject, jurisdiction) non-decreasing ratchet on the proof timestamp.
    ///      Blocks an older proof from overwriting a newer attestation -- the canonical
    ///      replay-extension attack where an attacker holds a "passed" proof and re-submits
    ///      it after state has degraded. The ratchet's effective value is the proof's
    ///      internal timestamp for types that expose one (COMPLIANCE/ATTESTATION/MEMBERSHIP/
    ///      NON_MEMBERSHIP), or `block.timestamp` for types that don't (RISK_SCORE/PATTERN).
    ///      Equal timestamps are allowed: legitimate same-block submissions of different
    ///      proof types for the same (subject, jurisdiction) must remain possible.
    function _ratchet(uint8 jurisdictionId, uint256 proofTimestamp) internal {
        uint256 last = _lastProofTimestamp[msg.sender][jurisdictionId];
        if (proofTimestamp < last) revert ProofTimestampNotMonotonic(proofTimestamp, last);
        if (proofTimestamp != last) {
            _lastProofTimestamp[msg.sender][jurisdictionId] = proofTimestamp;
        }
    }

    /// @notice Last ratcheted proof timestamp for a (subject, jurisdiction) pair.
    /// @dev Returns 0 when no proof has been recorded yet for the pair.
    function lastProofTimestamp(address subject, uint8 jurisdictionId) external view returns (uint256) {
        return _lastProofTimestamp[subject][jurisdictionId];
    }

    /// @dev Check that a proof timestamp is within MAX_PROOF_AGE of block.timestamp
    function _validateProofTimestamp(uint256 proofTimestamp) internal view {
        uint256 diff =
            block.timestamp > proofTimestamp ? block.timestamp - proofTimestamp : proofTimestamp - block.timestamp;
        if (diff > MAX_PROOF_AGE) revert ProofTimestampStale(proofTimestamp, block.timestamp);
    }

    /// @dev Validate that caller-supplied jurisdiction and providerSetHash match
    ///      the corresponding fields in the COMPLIANCE proof's public inputs,
    ///      and that the config_hash is a known (current or historical) config.
    function _validateComplianceInputs(uint8 jurisdictionId, bytes32 providerSetHash, bytes calldata publicInputs)
        internal
        view
        returns (uint256 proofTimestamp)
    {
        // COMPLIANCE public inputs layout (each 32 bytes):
        //   [0]: jurisdiction_id
        //   [1]: provider_set_hash
        //   [2]: config_hash
        //   [3]: timestamp
        //   [4]: meets_threshold
        //   [5]: submitter
        bytes32 proofJurisdiction = bytes32(publicInputs[0:32]);
        bytes32 proofProviderSet = bytes32(publicInputs[32:64]);
        bytes32 proofConfigHash = bytes32(publicInputs[64:96]);
        bytes32 proofMeetsThreshold = bytes32(publicInputs[128:160]);
        address proofSubmitter = address(uint160(uint256(bytes32(publicInputs[160:192]))));

        if (proofJurisdiction != bytes32(uint256(jurisdictionId))) revert PublicInputMismatch();
        if (proofProviderSet != providerSetHash) revert PublicInputMismatch();
        if (!_validConfigs[proofConfigHash]) revert InvalidConfigHash(proofConfigHash);
        if (proofMeetsThreshold != bytes32(uint256(1))) revert ProofResultNegative();
        if (proofSubmitter != msg.sender) revert SubmitterMismatch();
        if (_configContainsDeniedProvider(proofConfigHash)) {
            revert ProviderDenied(_firstDeniedProviderInConfig(proofConfigHash));
        }
        proofTimestamp = uint256(bytes32(publicInputs[96:128]));
        _validateProofTimestamp(proofTimestamp);
    }

    /// @dev Return the first denied provider ID found in `configHash`'s expansion.
    ///      Caller must have already verified at least one denied provider exists.
    function _firstDeniedProviderInConfig(bytes32 configHash) internal view returns (uint256) {
        uint256[] storage providers = _configProviders[configHash];
        uint256 length = providers.length;
        for (uint256 i; i < length;) {
            if (_deniedProviders[providers[i]]) return providers[i];
            unchecked {
                ++i;
            }
        }
        return 0; // unreachable when caller has confirmed via _configContainsDeniedProvider
    }

    /// @dev Validate that the config_hash in RISK_SCORE public inputs is a known config,
    ///      that semantic public inputs (proof_type, direction, bounds) are well-formed
    ///      and non-trivial, and that the result field indicates a positive outcome.
    ///      NOTE: RISK_SCORE has no timestamp in public inputs; staleness not enforced.
    function _validateRiskScoreInputs(bytes calldata publicInputs) internal view returns (uint256 proofTimestamp) {
        // RISK_SCORE has no proof-internal timestamp; ratchet uses block.timestamp instead
        proofTimestamp = block.timestamp;
        // RISK_SCORE public inputs layout (each 32 bytes):
        //   [0]: proof_type
        //   [1]: direction
        //   [2]: bound_lower
        //   [3]: bound_upper
        //   [4]: result
        //   [5]: config_hash
        //   [6]: provider_set_hash
        //   [7]: submitter
        uint256 proofType = uint256(bytes32(publicInputs[0:32]));
        uint256 direction = uint256(bytes32(publicInputs[32:64]));
        uint256 boundLower = uint256(bytes32(publicInputs[64:96]));
        uint256 boundUpper = uint256(bytes32(publicInputs[96:128]));
        bytes32 proofResult = bytes32(publicInputs[128:160]);
        bytes32 proofConfigHash = bytes32(publicInputs[160:192]);
        address proofSubmitter = address(uint160(uint256(bytes32(publicInputs[224:256]))));

        if (proofResult != bytes32(uint256(1))) revert ProofResultNegative();
        if (!_validConfigs[proofConfigHash]) revert InvalidConfigHash(proofConfigHash);
        if (proofSubmitter != msg.sender) revert SubmitterMismatch();

        // Reject trivial / undefined claims that would otherwise produce an attestation
        // marked meetsThreshold=true with no real semantic content.
        if (proofType == RISK_PROOF_THRESHOLD) {
            if (direction == RISK_DIRECTION_GT) {
                // "score > 0" is trivially true for any nonzero score; "score > 10000+" is impossible
                if (boundLower == 0 || boundLower >= MAX_RISK_SCORE_BPS) {
                    revert TrivialRiskBound(boundLower, boundUpper);
                }
            } else if (direction == RISK_DIRECTION_LT) {
                // "score < 0" impossible; "score < 10001+" trivially true
                if (boundLower == 0 || boundLower > MAX_RISK_SCORE_BPS) {
                    revert TrivialRiskBound(boundLower, boundUpper);
                }
            } else {
                revert InvalidRiskDirection(direction);
            }
        } else if (proofType == RISK_PROOF_RANGE) {
            if (boundLower >= boundUpper || boundUpper > MAX_RISK_SCORE_BPS) {
                revert InvalidRiskBound(boundLower, boundUpper);
            }
            // Reject the full-domain range [0, 10000] which any score satisfies
            if (boundLower == 0 && boundUpper == MAX_RISK_SCORE_BPS) {
                revert TrivialRiskBound(boundLower, boundUpper);
            }
        } else {
            revert InvalidRiskProofType(proofType);
        }
    }

    /// @dev Validate PATTERN public inputs.
    ///      Ensures analysis_type is in the supported set, result is positive,
    ///      reporting_threshold is registered, tx_set_hash is non-zero,
    ///      time_window meets minimum, and submitter matches msg.sender.
    ///      NOTE: PATTERN uses time_window (not a timestamp); staleness not enforced.
    ///      NOTE: callers that require a specific analysis (e.g. anti-structuring) MUST
    ///      verify the analysis_type field themselves; this validator only enforces
    ///      that it is well-formed.
    function _validatePatternInputs(bytes calldata publicInputs) internal view returns (uint256 proofTimestamp) {
        // PATTERN has no proof-internal timestamp (uses time_window); ratchet uses block.timestamp
        proofTimestamp = block.timestamp;
        // PATTERN public inputs layout (each 32 bytes):
        //   [0]: analysis_type
        //   [1]: result
        //   [2]: reporting_threshold
        //   [3]: time_window
        //   [4]: tx_set_hash
        //   [5]: submitter
        uint256 analysisType = uint256(bytes32(publicInputs[0:32]));
        if (
            analysisType != PATTERN_STRUCTURING && analysisType != PATTERN_VELOCITY
                && analysisType != PATTERN_ROUND_AMOUNT
        ) {
            revert InvalidAnalysisType(analysisType);
        }
        bytes32 proofResult = bytes32(publicInputs[32:64]);
        if (proofResult != bytes32(uint256(1))) revert ProofResultNegative();
        bytes32 reportingThreshold = bytes32(publicInputs[64:96]);
        if (!_validReportingThresholds[reportingThreshold]) {
            revert InvalidReportingThreshold(reportingThreshold);
        }
        uint256 timeWindow = uint256(bytes32(publicInputs[96:128]));
        if (timeWindow < MIN_TIME_WINDOW) revert TimeWindowTooSmall(timeWindow, MIN_TIME_WINDOW);
        bytes32 txSetHash = bytes32(publicInputs[128:160]);
        if (txSetHash == bytes32(0)) revert PublicInputMismatch();
        address proofSubmitter = address(uint160(uint256(bytes32(publicInputs[160:192]))));
        if (proofSubmitter != msg.sender) revert SubmitterMismatch();
    }

    /// @dev Validate ATTESTATION public inputs (post C-1 redesign).
    ///      Ensures provider_id is non-zero, is_valid is true, the proof's
    ///      credential_root is currently registered for that provider (not expired,
    ///      not revoked), the proof timestamp is fresh, and submitter == msg.sender.
    function _validateAttestationInputs(bytes calldata publicInputs) internal view returns (uint256 proofTimestamp) {
        // ATTESTATION public inputs layout (each 32 bytes):
        //   [0]: provider_id
        //   [1]: credential_type
        //   [2]: is_valid
        //   [3]: credential_root
        //   [4]: current_timestamp
        //   [5]: submitter
        uint256 providerId = uint256(bytes32(publicInputs[0:32]));
        if (providerId == 0) revert InvalidProviderId();

        bytes32 proofIsValid = bytes32(publicInputs[64:96]);
        if (proofIsValid != bytes32(uint256(1))) revert ProofResultNegative();

        bytes32 credentialRoot = bytes32(publicInputs[96:128]);
        CredentialRootInfo memory rootInfo = _credentialRoots[credentialRoot];
        if (rootInfo.registeredAt == 0) revert CredentialRootNotFound(credentialRoot);
        if (rootInfo.revoked) revert CredentialRootExpired(credentialRoot, rootInfo.registeredAt);
        if (block.timestamp > uint256(rootInfo.registeredAt) + CREDENTIAL_ROOT_TTL) {
            revert CredentialRootExpired(credentialRoot, rootInfo.registeredAt);
        }
        if (rootInfo.providerId != providerId) {
            revert CredentialRootProviderMismatch(rootInfo.providerId, providerId);
        }

        proofTimestamp = uint256(bytes32(publicInputs[128:160]));
        _validateProofTimestamp(proofTimestamp);
        address proofSubmitter = address(uint160(uint256(bytes32(publicInputs[160:192]))));
        if (proofSubmitter != msg.sender) revert SubmitterMismatch();
    }

    /// @dev Validate MEMBERSHIP public inputs.
    ///      Ensures is_member is true, merkle_root is registered, and submitter matches msg.sender.
    function _validateMembershipInputs(bytes calldata publicInputs) internal view returns (uint256 proofTimestamp) {
        // MEMBERSHIP public inputs layout (each 32 bytes):
        //   [0]: merkle_root
        //   [1]: set_id
        //   [2]: timestamp
        //   [3]: is_member
        //   [4]: submitter
        bytes32 merkleRoot = bytes32(publicInputs[0:32]);
        if (!_validMerkleRoots[merkleRoot]) revert InvalidMerkleRoot(merkleRoot);
        proofTimestamp = uint256(bytes32(publicInputs[64:96]));
        _validateProofTimestamp(proofTimestamp);
        bytes32 proofIsMember = bytes32(publicInputs[96:128]);
        if (proofIsMember != bytes32(uint256(1))) revert ProofResultNegative();
        address proofSubmitter = address(uint160(uint256(bytes32(publicInputs[128:160]))));
        if (proofSubmitter != msg.sender) revert SubmitterMismatch();
    }

    /// @dev Validate NON_MEMBERSHIP public inputs.
    ///      Ensures is_non_member is true, merkle_root is registered, and submitter matches msg.sender.
    function _validateNonMembershipInputs(bytes calldata publicInputs) internal view returns (uint256 proofTimestamp) {
        // NON_MEMBERSHIP public inputs layout (each 32 bytes):
        //   [0]: merkle_root
        //   [1]: set_id
        //   [2]: timestamp
        //   [3]: is_non_member
        //   [4]: submitter
        bytes32 merkleRoot = bytes32(publicInputs[0:32]);
        if (!_validMerkleRoots[merkleRoot]) revert InvalidMerkleRoot(merkleRoot);
        proofTimestamp = uint256(bytes32(publicInputs[64:96]));
        _validateProofTimestamp(proofTimestamp);
        bytes32 proofIsNonMember = bytes32(publicInputs[96:128]);
        if (proofIsNonMember != bytes32(uint256(1))) revert ProofResultNegative();
        address proofSubmitter = address(uint160(uint256(bytes32(publicInputs[128:160]))));
        if (proofSubmitter != msg.sender) revert SubmitterMismatch();
    }
}
