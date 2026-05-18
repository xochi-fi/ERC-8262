// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC8262Oracle} from "../src/ERC8262Oracle.sol";
import {ERC8262Verifier} from "../src/ERC8262Verifier.sol";
import {IERC8262Oracle} from "../src/interfaces/IERC8262Oracle.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {EIP712Attestation} from "../src/libraries/EIP712Attestation.sol";

contract StubVerifier is IUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract EIP712AttestationTest is Test {
    ERC8262Oracle internal oracle;
    ERC8262Oracle internal oracle2;

    function _defaultProviders() internal pure returns (uint256[] memory ps) {
        ps = new uint256[](1);
        ps[0] = 1;
    }

    function setUp() public {
        address owner = makeAddr("owner");
        ERC8262Verifier verifier = new ERC8262Verifier(owner);
        oracle = new ERC8262Oracle(address(verifier), owner, keccak256("config"), _defaultProviders());

        ERC8262Verifier verifier2 = new ERC8262Verifier(owner);
        oracle2 = new ERC8262Oracle(address(verifier2), owner, keccak256("config"), _defaultProviders());
    }

    function _sampleAttestation() internal pure returns (IERC8262Oracle.ComplianceAttestation memory) {
        return IERC8262Oracle.ComplianceAttestation({
            subject: address(0xdead),
            jurisdictionId: 0,
            proofType: 0x01,
            meetsThreshold: true,
            timestamp: 1700000000,
            expiresAt: 1700086400,
            proofHash: keccak256("proof"),
            providerSetHash: keccak256("providers"),
            publicInputsHash: keccak256("inputs"),
            verifierUsed: address(0xbeef)
        });
    }

    function test_hashAttestation_deterministic() public view {
        IERC8262Oracle.ComplianceAttestation memory att = _sampleAttestation();
        bytes32 h1 = oracle.hashAttestation(att);
        bytes32 h2 = oracle.hashAttestation(att);
        assertEq(h1, h2);
        assertTrue(h1 != bytes32(0));
    }

    function test_hashAttestation_differsByField() public view {
        IERC8262Oracle.ComplianceAttestation memory att1 = _sampleAttestation();
        IERC8262Oracle.ComplianceAttestation memory att2 = _sampleAttestation();
        att2.jurisdictionId = 1;
        assertFalse(oracle.hashAttestation(att1) == oracle.hashAttestation(att2));

        IERC8262Oracle.ComplianceAttestation memory att3 = _sampleAttestation();
        att3.subject = address(0xbeef);
        assertFalse(oracle.hashAttestation(att1) == oracle.hashAttestation(att3));

        IERC8262Oracle.ComplianceAttestation memory att4 = _sampleAttestation();
        att4.proofType = 0x02;
        assertFalse(oracle.hashAttestation(att1) == oracle.hashAttestation(att4));

        IERC8262Oracle.ComplianceAttestation memory att5 = _sampleAttestation();
        att5.meetsThreshold = false;
        assertFalse(oracle.hashAttestation(att1) == oracle.hashAttestation(att5));

        IERC8262Oracle.ComplianceAttestation memory att6 = _sampleAttestation();
        att6.timestamp = 1700000001;
        assertFalse(oracle.hashAttestation(att1) == oracle.hashAttestation(att6));
    }

    function test_domainSeparator_includesChainId() public {
        bytes32 sep1 = oracle.DOMAIN_SEPARATOR();

        vm.chainId(42161); // Arbitrum
        bytes32 sep2 = oracle.DOMAIN_SEPARATOR();

        assertFalse(sep1 == sep2);
    }

    function test_domainSeparator_changesPerContract() public view {
        bytes32 sep1 = oracle.DOMAIN_SEPARATOR();
        bytes32 sep2 = oracle2.DOMAIN_SEPARATOR();
        assertFalse(sep1 == sep2);
    }

    function test_toTypedDataHash_matchesManualComputation() public view {
        IERC8262Oracle.ComplianceAttestation memory att = _sampleAttestation();
        bytes32 domainSep = oracle.DOMAIN_SEPARATOR();
        bytes32 structHash = oracle.hashAttestation(att);

        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
        bytes32 actual = EIP712Attestation.toTypedDataHash(domainSep, att);

        assertEq(actual, expected);
    }
}
