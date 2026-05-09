// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {XochiZKPOracle} from "../src/XochiZKPOracle.sol";
import {XochiZKPVerifier} from "../src/XochiZKPVerifier.sol";
import {IXochiZKPOracle} from "../src/interfaces/IXochiZKPOracle.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";

contract AlwaysPassVerifierInv is IUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract Handler is Test {
    XochiZKPOracle public oracle;
    XochiZKPVerifier public verifier;

    uint256 internal _proofNonce;
    uint256 public proofCount;
    uint256 public configUpdateCount;

    bytes32[] public submittedProofHashes;
    address[] public submitters;
    uint256[] public submissionTimestamps;
    uint256[] public submissionTTLs;

    bytes32[] public oldConfigs;

    bytes32 internal constant INITIAL_CONFIG = keccak256("initial-config");
    bytes32 internal constant DEFAULT_PROVIDER_SET_HASH = bytes32(uint256(0xaabb));

    constructor(XochiZKPOracle _oracle, XochiZKPVerifier _verifier) {
        oracle = _oracle;
        verifier = _verifier;
    }

    function _defaultProviders() internal pure returns (uint256[] memory ps) {
        ps = new uint256[](1);
        ps[0] = 1;
    }

    function submitComplianceProof(uint8 jurisdictionSeed) external {
        uint8 jurisdictionId = jurisdictionSeed % 4;
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(jurisdictionId)),
            DEFAULT_PROVIDER_SET_HASH,
            oracle.providerConfigHash(),
            bytes32(uint256(1700000)),
            bytes32(uint256(1)),
            bytes32(uint256(uint160(address(this)))) // submitter = this handler
        );

        bytes32 proofHash = oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);

        IXochiZKPOracle.ComplianceAttestation memory att = oracle.submitCompliance(
            jurisdictionId, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH
        );

        submittedProofHashes.push(proofHash);
        submitters.push(att.subject);
        submissionTimestamps.push(att.timestamp);
        submissionTTLs.push(oracle.attestationTTL());
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
    }

    function setVerifierOnVerifier(uint8 proofTypeSeed) external {
        uint8 proofType = uint8(bound(proofTypeSeed, 1, 6));
        AlwaysPassVerifierInv newV = new AlwaysPassVerifierInv();
        address own = verifier.owner();
        vm.prank(own);
        verifier.proposeVerifier(proofType, address(newV));
        vm.warp(block.timestamp + 24 hours);
        vm.prank(own);
        verifier.executeVerifierUpdate(proofType);
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
    XochiZKPOracle internal oracle;
    XochiZKPVerifier internal verifier;
    Handler internal handler;

    bytes32 internal constant INITIAL_CONFIG = keccak256("initial-config");

    function _defaultProviders() internal pure returns (uint256[] memory ps) {
        ps = new uint256[](1);
        ps[0] = 1;
    }

    function setUp() public {
        address owner = address(this);
        verifier = new XochiZKPVerifier(owner);
        oracle = new XochiZKPOracle(address(verifier), owner, INITIAL_CONFIG, _defaultProviders());

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
            IXochiZKPOracle.ComplianceAttestation memory att = oracle.getHistoricalProof(proofHash);
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
            IXochiZKPOracle.ComplianceAttestation memory att = oracle.getHistoricalProof(proofHash);
            assertEq(att.subject, handler.submitters(i));
        }
    }

    function invariant_ttlConsistency() public view {
        for (uint256 i; i < handler.proofCount(); i++) {
            bytes32 proofHash = handler.submittedProofHashes(i);
            IXochiZKPOracle.ComplianceAttestation memory att = oracle.getHistoricalProof(proofHash);
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
}
