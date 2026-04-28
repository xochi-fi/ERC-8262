// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {XochiZKPOracle} from "../src/XochiZKPOracle.sol";
import {XochiZKPVerifier} from "../src/XochiZKPVerifier.sol";
import {IXochiZKPOracle} from "../src/interfaces/IXochiZKPOracle.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {EIP712Attestation} from "../src/libraries/EIP712Attestation.sol";

contract StubVerifier is IUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract EIP712AttestationTest is Test {
    XochiZKPOracle internal oracle;
    XochiZKPOracle internal oracle2;

    function setUp() public {
        address owner = makeAddr("owner");
        XochiZKPVerifier verifier = new XochiZKPVerifier(owner);
        oracle = new XochiZKPOracle(address(verifier), owner, keccak256("config"));

        XochiZKPVerifier verifier2 = new XochiZKPVerifier(owner);
        oracle2 = new XochiZKPOracle(address(verifier2), owner, keccak256("config"));
    }

    function _sampleAttestation() internal pure returns (IXochiZKPOracle.ComplianceAttestation memory) {
        return IXochiZKPOracle.ComplianceAttestation({
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
        IXochiZKPOracle.ComplianceAttestation memory att = _sampleAttestation();
        bytes32 h1 = oracle.hashAttestation(att);
        bytes32 h2 = oracle.hashAttestation(att);
        assertEq(h1, h2);
        assertTrue(h1 != bytes32(0));
    }

    function test_hashAttestation_differsByField() public view {
        IXochiZKPOracle.ComplianceAttestation memory att1 = _sampleAttestation();
        IXochiZKPOracle.ComplianceAttestation memory att2 = _sampleAttestation();
        att2.jurisdictionId = 1;
        assertFalse(oracle.hashAttestation(att1) == oracle.hashAttestation(att2));

        IXochiZKPOracle.ComplianceAttestation memory att3 = _sampleAttestation();
        att3.subject = address(0xbeef);
        assertFalse(oracle.hashAttestation(att1) == oracle.hashAttestation(att3));

        IXochiZKPOracle.ComplianceAttestation memory att4 = _sampleAttestation();
        att4.proofType = 0x02;
        assertFalse(oracle.hashAttestation(att1) == oracle.hashAttestation(att4));

        IXochiZKPOracle.ComplianceAttestation memory att5 = _sampleAttestation();
        att5.meetsThreshold = false;
        assertFalse(oracle.hashAttestation(att1) == oracle.hashAttestation(att5));

        IXochiZKPOracle.ComplianceAttestation memory att6 = _sampleAttestation();
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
        IXochiZKPOracle.ComplianceAttestation memory att = _sampleAttestation();
        bytes32 domainSep = oracle.DOMAIN_SEPARATOR();
        bytes32 structHash = oracle.hashAttestation(att);

        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
        bytes32 actual = EIP712Attestation.toTypedDataHash(domainSep, att);

        assertEq(actual, expected);
    }
}
