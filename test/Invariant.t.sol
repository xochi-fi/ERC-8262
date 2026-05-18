// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC8262Oracle} from "../src/ERC8262Oracle.sol";
import {ERC8262Verifier} from "../src/ERC8262Verifier.sol";
import {IERC8262Oracle} from "../src/interfaces/IERC8262Oracle.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";

contract AlwaysPassVerifierInv is IUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract Handler is Test {
    ERC8262Oracle public oracle;
    ERC8262Verifier public verifier;

    uint256 internal _proofNonce;
    uint256 public proofCount;
    uint256 public configUpdateCount;

    bytes32[] public submittedProofHashes;
    address[] public submitters;
    uint256[] public submissionTimestamps;
    uint256[] public submissionTTLs;

    bytes32[] public oldConfigs;
    bytes32[] public revokedConfigs;

    bytes32[] public registeredMerkleRoots;
    bytes32[] public revokedMerkleRoots;
    mapping(bytes32 => bool) public merkleRootEverRegistered;
    mapping(bytes32 => bool) public merkleRootEverRevoked;

    /// @notice Highest successful proofTimestamp seen per (handler-as-subject, jurisdiction).
    /// @dev The handler is the submitter for every successful call, so it is also the subject.
    mapping(uint8 => uint256) public maxProofTimestamp;

    /// @notice Unsigned-compliance jurisdictions only. US (1) and SG (3) require signed signals.
    uint8[2] internal _unsignedJurisdictions = [0, 2]; // EU, UK

    bytes32 internal constant INITIAL_CONFIG = keccak256("initial-config");
    bytes32 internal constant DEFAULT_PROVIDER_SET_HASH = bytes32(uint256(0xaabb));

    constructor(ERC8262Oracle _oracle, ERC8262Verifier _verifier) {
        oracle = _oracle;
        verifier = _verifier;
    }

    function _defaultProviders() internal pure returns (uint256[] memory ps) {
        ps = new uint256[](1);
        ps[0] = 1;
    }

    function submitComplianceProof(uint8 jurisdictionSeed) external {
        uint8 jurisdictionId = _unsignedJurisdictions[jurisdictionSeed % _unsignedJurisdictions.length];
        uint256 proofTimestamp = block.timestamp;
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(jurisdictionId)),
            DEFAULT_PROVIDER_SET_HASH,
            oracle.providerConfigHash(),
            bytes32(proofTimestamp),
            bytes32(uint256(1)),
            bytes32(uint256(uint160(address(this))))
        );

        bytes32 proofHash = oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);

        IERC8262Oracle.ComplianceAttestation memory att = oracle.submitCompliance(
            jurisdictionId, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH
        );

        submittedProofHashes.push(proofHash);
        submitters.push(att.subject);
        submissionTimestamps.push(att.timestamp);
        submissionTTLs.push(oracle.attestationTTL());
        if (proofTimestamp > maxProofTimestamp[jurisdictionId]) {
            maxProofTimestamp[jurisdictionId] = proofTimestamp;
        }
        proofCount++;
    }

    function updateConfig(bytes32 salt) external {
        bytes32 newConfig = keccak256(abi.encodePacked("config-", salt, configUpdateCount));
        bytes32 current = oracle.providerConfigHash();
        if (newConfig == current) return;
        if (oracle.configHistoryLength() >= 256) return;

        oldConfigs.push(current);
        vm.prank(oracle.owner());
        oracle.updateProviderConfig(newConfig, "", _defaultProviders());
        configUpdateCount++;
    }

    function revokeOldConfig(uint256 index) external {
        if (oldConfigs.length == 0) return;
        index = index % oldConfigs.length;
        bytes32 target = oldConfigs[index];

        if (target == oracle.providerConfigHash()) return;
        if (!oracle.isValidConfig(target)) return;

        vm.prank(oracle.owner());
        oracle.revokeConfig(target);
        revokedConfigs.push(target);
    }

    function registerMerkleRoot(bytes32 salt) external {
        bytes32 root = keccak256(abi.encodePacked("root-", salt, registeredMerkleRoots.length));
        if (oracle.isValidMerkleRoot(root)) return;
        if (merkleRootEverRevoked[root]) return;

        vm.prank(oracle.owner());
        oracle.registerMerkleRoot(root);
        if (!merkleRootEverRegistered[root]) {
            registeredMerkleRoots.push(root);
            merkleRootEverRegistered[root] = true;
        }
    }

    function revokeRegisteredMerkleRoot(uint256 index) external {
        if (registeredMerkleRoots.length == 0) return;
        index = index % registeredMerkleRoots.length;
        bytes32 root = registeredMerkleRoots[index];
        if (!oracle.isValidMerkleRoot(root)) return;

        vm.prank(oracle.owner());
        oracle.revokeMerkleRoot(root);
        if (!merkleRootEverRevoked[root]) {
            revokedMerkleRoots.push(root);
            merkleRootEverRevoked[root] = true;
        }
    }

    function setVerifierOnVerifier(uint8 proofTypeSeed) external {
        uint8 proofType = uint8(bound(proofTypeSeed, 1, 6));
        AlwaysPassVerifierInv newV = new AlwaysPassVerifierInv();
        address own = verifier.owner();
        vm.prank(own);
        verifier.proposeVerifier(proofType, address(newV), address(newV).codehash);
        vm.warp(block.timestamp + 24 hours);
        vm.prank(own);
        verifier.executeVerifierUpdate(proofType);
    }

    function unsignedJurisdictionCount() external view returns (uint256) {
        return _unsignedJurisdictions.length;
    }

    function unsignedJurisdiction(uint256 i) external view returns (uint8) {
        return _unsignedJurisdictions[i];
    }

    function registeredMerkleRootsLength() external view returns (uint256) {
        return registeredMerkleRoots.length;
    }

    function revokedConfigsLength() external view returns (uint256) {
        return revokedConfigs.length;
    }

    function _uniqueProof() internal returns (bytes memory) {
        _proofNonce++;
        bytes memory proof = new bytes(2144);
        bytes32 nonceBytes = bytes32(_proofNonce);
        for (uint256 i; i < 32; i++) {
            proof[i] = nonceBytes[i];
        }
        return proof;
    }
}

contract InvariantTest is Test {
    ERC8262Oracle internal oracle;
    ERC8262Verifier internal verifier;
    Handler internal handler;

    bytes32 internal constant INITIAL_CONFIG = keccak256("initial-config");

    function _defaultProviders() internal pure returns (uint256[] memory ps) {
        ps = new uint256[](1);
        ps[0] = 1;
    }

    function setUp() public {
        // Advance time so proofTimestamp = block.timestamp is positive and within MAX_PROOF_AGE.
        vm.warp(1_700_000_000);

        address owner = address(this);
        verifier = new ERC8262Verifier(owner);
        oracle = new ERC8262Oracle(address(verifier), owner, INITIAL_CONFIG, _defaultProviders());

        AlwaysPassVerifierInv stub = new AlwaysPassVerifierInv();
        for (uint8 i = ProofTypes.COMPLIANCE; i <= ProofTypes.NON_MEMBERSHIP; i++) {
            verifier.setVerifierInitial(i, address(stub));
        }

        handler = new Handler(oracle, verifier);

        targetContract(address(handler));
    }

    function invariant_proofImmutability() public view {
        for (uint256 i; i < handler.proofCount(); i++) {
            bytes32 proofHash = handler.submittedProofHashes(i);
            IERC8262Oracle.ComplianceAttestation memory att = oracle.getHistoricalProof(proofHash);
            assertTrue(att.timestamp > 0);
        }
    }

    function invariant_configHistoryAppendOnly() public view {
        uint256 expected = 1 + handler.configUpdateCount();
        assertEq(oracle.configHistoryLength(), expected);
    }

    function invariant_subjectBinding() public view {
        for (uint256 i; i < handler.proofCount(); i++) {
            bytes32 proofHash = handler.submittedProofHashes(i);
            IERC8262Oracle.ComplianceAttestation memory att = oracle.getHistoricalProof(proofHash);
            assertEq(att.subject, handler.submitters(i));
        }
    }

    function invariant_ttlConsistency() public view {
        for (uint256 i; i < handler.proofCount(); i++) {
            bytes32 proofHash = handler.submittedProofHashes(i);
            IERC8262Oracle.ComplianceAttestation memory att = oracle.getHistoricalProof(proofHash);
            uint256 expectedTTL = handler.submissionTTLs(i);
            assertEq(att.expiresAt, handler.submissionTimestamps(i) + expectedTTL);
        }
    }

    function invariant_verifierHistoryAppendOnly() public view {
        for (uint8 pt = ProofTypes.COMPLIANCE; pt <= ProofTypes.NON_MEMBERSHIP; pt++) {
            uint256 version = verifier.getVerifierVersion(pt);
            assertTrue(version >= 1);
        }
    }

    /// @notice For each (handler, jurisdiction) tracked, the oracle's ratchet equals the highest
    ///         successful proofTimestamp ever submitted. Catches any code path that allowed an
    ///         older proof to overwrite a newer attestation.
    function invariant_ratchetMatchesMaxSubmitted() public view {
        for (uint256 i; i < handler.unsignedJurisdictionCount(); i++) {
            uint8 jId = handler.unsignedJurisdiction(i);
            uint256 expected = handler.maxProofTimestamp(jId);
            uint256 actual = oracle.lastProofTimestamp(address(handler), jId);
            assertEq(actual, expected);
        }
    }

    /// @notice Once a provider config is revoked, isValidConfig must remain false forever.
    function invariant_revokedConfigsStayRevoked() public view {
        for (uint256 i; i < handler.revokedConfigsLength(); i++) {
            bytes32 c = handler.revokedConfigs(i);
            assertFalse(oracle.isValidConfig(c));
        }
    }

    /// @notice Merkle root state machine: handler-tracked roots are valid iff they were registered
    ///         and not subsequently revoked. The handler avoids re-registering revoked roots so the
    ///         tracker stays a one-way transition; this catches any oracle-side bug that flipped
    ///         the flag without our knowledge.
    function invariant_merkleRootStateMachine() public view {
        for (uint256 i; i < handler.registeredMerkleRootsLength(); i++) {
            bytes32 root = handler.registeredMerkleRoots(i);
            if (handler.merkleRootEverRevoked(root)) {
                assertFalse(oracle.isValidMerkleRoot(root));
            } else {
                assertTrue(oracle.isValidMerkleRoot(root));
            }
        }
    }
}
