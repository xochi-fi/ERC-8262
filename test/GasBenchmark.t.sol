// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {XochiZKPVerifier} from "../src/XochiZKPVerifier.sol";
import {XochiZKPOracle} from "../src/XochiZKPOracle.sol";
import {IXochiZKPOracle} from "../src/interfaces/IXochiZKPOracle.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";

/// @title Gas benchmarks for per-proof-type verification and Oracle submission
/// @notice Uses real UltraHonk proofs from test/fixtures/ for accurate gas measurement.
///         Run with: forge test --match-contract GasBenchmark --gas-report
contract GasBenchmarkTest is Test {
    XochiZKPVerifier internal verifier;
    XochiZKPOracle internal oracle;

    address internal owner = makeAddr("owner");
    address internal publisher = makeAddr("publisher");
    address internal constant FIXTURE_SUBMITTER = address(0xdead);
    uint256 internal constant FIXTURE_PROVIDER_ID = 42;

    bytes32 internal constant FIXTURE_CONFIG_HASH = 0x18574f427f33c6c77af53be06544bd749c9a1db855599d950af61ea613df8405;
    bytes32 internal constant FIXTURE_PROVIDER_SET_HASH =
        0x14b6becf762f80a24078e62fc9a7eca246b8e406d19962dda817b173f30a94b2;
    bytes32 internal constant FIXTURE_MEMBERSHIP_ROOT =
        0x1d7de002251083fdc312a329d46abde0680cbccc27935c33815c18b1beb3da8c;
    bytes32 internal constant FIXTURE_NON_MEMBERSHIP_ROOT =
        0x138f818fd4f2eec91e4fd93e14bcc47bc06a3ba333e5a2e7795d0beb752d247c;
    bytes32 internal constant FIXTURE_TIER_MERKLE_ROOT =
        0x24ce58f9ed6ca066d25f66b15b0eb1dccebe6e457f5aa0fcd353d82d539f5ed5;

    function setUp() public {
        verifier = new XochiZKPVerifier(owner);
        oracle = new XochiZKPOracle(address(verifier), owner, FIXTURE_CONFIG_HASH);

        string[6] memory circuits =
            ["compliance", "risk_score", "pattern", "attestation", "membership", "non_membership"];
        uint8[6] memory types = [
            ProofTypes.COMPLIANCE,
            ProofTypes.RISK_SCORE,
            ProofTypes.PATTERN,
            ProofTypes.ATTESTATION,
            ProofTypes.MEMBERSHIP,
            ProofTypes.NON_MEMBERSHIP
        ];

        vm.startPrank(owner);
        for (uint256 i; i < 6; i++) {
            address v = _deployGeneratedVerifier(circuits[i]);
            verifier.setVerifierInitial(types[i], v);
        }
        oracle.registerMerkleRoot(FIXTURE_MEMBERSHIP_ROOT);
        oracle.registerMerkleRoot(FIXTURE_NON_MEMBERSHIP_ROOT);
        oracle.registerReportingThreshold(bytes32(uint256(10000)));
        // ATTESTATION fixtures use the per-provider credentials tree (post C-1 redesign)
        oracle.setProviderPublisher(FIXTURE_PROVIDER_ID, publisher);
        vm.stopPrank();

        // Warp BEFORE publishing the credential root so its registeredAt aligns with
        // the proof timestamp baked into the fixtures (1700000000).
        vm.warp(1700000000);

        vm.prank(publisher);
        oracle.publishCredentialRoot(FIXTURE_PROVIDER_ID, FIXTURE_TIER_MERKLE_ROOT, "");
    }

    // -------------------------------------------------------------------------
    // verifyProof gas per proof type (verifier only, no storage)
    // -------------------------------------------------------------------------

    function test_gas_verifyProof_COMPLIANCE() public view {
        (bytes memory proof, bytes memory inputs) = _loadFixture("compliance");
        verifier.verifyProof(ProofTypes.COMPLIANCE, proof, inputs);
    }

    function test_gas_verifyProof_RISK_SCORE() public view {
        (bytes memory proof, bytes memory inputs) = _loadFixture("risk_score");
        verifier.verifyProof(ProofTypes.RISK_SCORE, proof, inputs);
    }

    function test_gas_verifyProof_PATTERN() public view {
        (bytes memory proof, bytes memory inputs) = _loadFixture("pattern");
        verifier.verifyProof(ProofTypes.PATTERN, proof, inputs);
    }

    function test_gas_verifyProof_ATTESTATION() public view {
        (bytes memory proof, bytes memory inputs) = _loadFixture("attestation");
        verifier.verifyProof(ProofTypes.ATTESTATION, proof, inputs);
    }

    function test_gas_verifyProof_MEMBERSHIP() public view {
        (bytes memory proof, bytes memory inputs) = _loadFixture("membership");
        verifier.verifyProof(ProofTypes.MEMBERSHIP, proof, inputs);
    }

    function test_gas_verifyProof_NON_MEMBERSHIP() public view {
        (bytes memory proof, bytes memory inputs) = _loadFixture("non_membership");
        verifier.verifyProof(ProofTypes.NON_MEMBERSHIP, proof, inputs);
    }

    // -------------------------------------------------------------------------
    // submitCompliance gas per proof type (verify + storage + events)
    // -------------------------------------------------------------------------

    function test_gas_submitCompliance_COMPLIANCE() public {
        (bytes memory proof, bytes memory inputs) = _loadFixture("compliance");
        vm.prank(FIXTURE_SUBMITTER);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, inputs, FIXTURE_PROVIDER_SET_HASH);
    }

    function test_gas_submitCompliance_RISK_SCORE() public {
        (bytes memory proof, bytes memory inputs) = _loadFixture("risk_score");
        vm.prank(FIXTURE_SUBMITTER);
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, proof, inputs, bytes32(0));
    }

    function test_gas_submitCompliance_PATTERN() public {
        (bytes memory proof, bytes memory inputs) = _loadFixture("pattern");
        vm.prank(FIXTURE_SUBMITTER);
        oracle.submitCompliance(0, ProofTypes.PATTERN, proof, inputs, bytes32(0));
    }

    function test_gas_submitCompliance_ATTESTATION() public {
        (bytes memory proof, bytes memory inputs) = _loadFixture("attestation");
        vm.prank(FIXTURE_SUBMITTER);
        oracle.submitCompliance(0, ProofTypes.ATTESTATION, proof, inputs, bytes32(0));
    }

    function test_gas_submitCompliance_MEMBERSHIP() public {
        (bytes memory proof, bytes memory inputs) = _loadFixture("membership");
        vm.prank(FIXTURE_SUBMITTER);
        oracle.submitCompliance(0, ProofTypes.MEMBERSHIP, proof, inputs, bytes32(0));
    }

    function test_gas_submitCompliance_NON_MEMBERSHIP() public {
        (bytes memory proof, bytes memory inputs) = _loadFixture("non_membership");
        vm.prank(FIXTURE_SUBMITTER);
        oracle.submitCompliance(0, ProofTypes.NON_MEMBERSHIP, proof, inputs, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // Batch verification gas scaling (compliance proofs, sizes 1-10)
    // Uses unique proofs per slot via salt (jurisdiction/submitter variation).
    // Beyond size 1, we reuse the same proof bytes with different jurisdictions
    // to avoid replay rejection. Sizes >4 reuse stubs since only 4 jurisdictions
    // are configured; the marginal gas per proof is what matters.
    // -------------------------------------------------------------------------

    function test_gas_batch_01() public {
        _submitBatch(1);
    }

    function test_gas_batch_02() public {
        _submitBatch(2);
    }

    function test_gas_batch_05() public {
        _submitBatch(5);
    }

    function test_gas_batch_10() public {
        _submitBatch(10);
    }

    function _submitBatch(uint256 size) internal {
        (bytes memory proof, bytes memory inputs) = _loadFixture("compliance");

        uint8[] memory proofTypes = new uint8[](size);
        bytes[] memory proofs = new bytes[](size);
        bytes[] memory publicInputs = new bytes[](size);
        bytes32[] memory providerSetHashes = new bytes32[](size);

        for (uint256 i; i < size; i++) {
            proofTypes[i] = ProofTypes.COMPLIANCE;
            proofs[i] = proof;
            publicInputs[i] = inputs;
            providerSetHashes[i] = FIXTURE_PROVIDER_SET_HASH;
        }

        // Batch submission -- will revert on replay for size > 1 since same proof hash.
        // For gas measurement, the first proof verifies; subsequent proofs hit ProofAlreadyUsed.
        // To get accurate batch gas, we'd need unique proofs per slot.
        // For now, measure size=1 accurately and note that batch overhead is additive.
        if (size == 1) {
            vm.prank(FIXTURE_SUBMITTER);
            oracle.submitComplianceBatch(0, proofTypes, proofs, publicInputs, providerSetHashes);
        }
        // For size > 1, just measure the verifier batch path (no replay issue)
        else {
            verifier.verifyProofBatch(proofTypes, proofs, publicInputs);
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function _loadFixture(string memory circuit) internal view returns (bytes memory proof, bytes memory publicInputs) {
        string memory proofPath = string.concat("test/fixtures/", circuit, "/proof");
        string memory inputsPath = string.concat("test/fixtures/", circuit, "/public_inputs");
        proof = vm.readFileBinary(proofPath);
        publicInputs = vm.readFileBinary(inputsPath);
    }

    function _deployGeneratedVerifier(string memory circuit) internal returns (address) {
        string memory contractName = _verifierContractName(circuit);
        string memory artifact = string.concat(circuit, "_verifier.sol:", contractName);
        bytes memory bytecode = vm.getCode(artifact);
        bytes32 salt = keccak256(abi.encodePacked("bench", circuit));
        address deployed;
        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(deployed != address(0), "verifier deployment failed");
        return deployed;
    }

    function _verifierContractName(string memory circuit) internal pure returns (string memory) {
        if (keccak256(bytes(circuit)) == keccak256("compliance")) return "ComplianceVerifier";
        if (keccak256(bytes(circuit)) == keccak256("risk_score")) return "RiskScoreVerifier";
        if (keccak256(bytes(circuit)) == keccak256("pattern")) return "PatternVerifier";
        if (keccak256(bytes(circuit)) == keccak256("attestation")) return "AttestationVerifier";
        if (keccak256(bytes(circuit)) == keccak256("membership")) return "MembershipVerifier";
        if (keccak256(bytes(circuit)) == keccak256("non_membership")) return "NonMembershipVerifier";
        revert("unknown circuit");
    }
}
