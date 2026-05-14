// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {XochiZKPOracle} from "../src/XochiZKPOracle.sol";
import {XochiZKPVerifier} from "../src/XochiZKPVerifier.sol";
import {IXochiZKPOracle} from "../src/interfaces/IXochiZKPOracle.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";

contract AlwaysPassVerifier is IUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract AttestationRatchetTest is Test {
    XochiZKPOracle internal oracle;
    XochiZKPVerifier internal verifier;
    AlwaysPassVerifier internal stub;

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    bytes32 internal constant INITIAL_CONFIG = keccak256("config");
    bytes32 internal constant PROVIDER_SET_HASH = keccak256("providers");

    function _defaultProviders() internal pure returns (uint256[] memory ps) {
        ps = new uint256[](1);
        ps[0] = 1;
    }

    function setUp() public {
        verifier = new XochiZKPVerifier(owner);
        oracle = new XochiZKPOracle(address(verifier), owner, INITIAL_CONFIG, _defaultProviders());
        stub = new AlwaysPassVerifier();

        vm.startPrank(owner);
        for (uint8 i = ProofTypes.COMPLIANCE; i <= ProofTypes.NON_MEMBERSHIP; i++) {
            verifier.setVerifierInitial(i, address(stub));
        }
        vm.stopPrank();

        // Move forward so MAX_PROOF_AGE checks have headroom
        vm.warp(1_700_000_000);
    }

    function _complianceInputs(uint8 jurisdictionId, address submitter, uint256 proofTimestamp)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes32(uint256(jurisdictionId)),
            PROVIDER_SET_HASH,
            INITIAL_CONFIG,
            bytes32(proofTimestamp),
            bytes32(uint256(1)), // meets_threshold
            bytes32(uint256(uint160(submitter)))
        );
    }

    function _proof(uint256 nonce) internal pure returns (bytes memory) {
        bytes memory p = new bytes(456);
        assembly {
            mstore(add(p, 32), nonce)
        }
        return p;
    }

    // -------------------------------------------------------------------------
    // Forward progression accepted
    // -------------------------------------------------------------------------

    function test_ratchet_acceptsForwardProgression() public {
        uint256 t0 = block.timestamp;
        vm.startPrank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _proof(1), _complianceInputs(0, alice, t0), PROVIDER_SET_HASH);

        vm.warp(t0 + 100);
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _proof(2), _complianceInputs(0, alice, t0 + 100), PROVIDER_SET_HASH
        );
        vm.stopPrank();

        assertEq(oracle.lastProofTimestamp(alice, 0), t0 + 100);
    }

    function test_ratchet_acceptsEqualTimestamp_differentProofType() public {
        // Same block, COMPLIANCE then ATTESTATION using block.timestamp -- ratchet must allow.
        // Note: ATTESTATION requires a published credential root, but we only need to confirm
        // the ratchet doesn't reject equal timestamps -- a second COMPLIANCE at same timestamp
        // exercises the same code path.
        uint256 t0 = block.timestamp;
        vm.startPrank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _proof(1), _complianceInputs(0, alice, t0), PROVIDER_SET_HASH);
        // Second submission at the SAME timestamp must succeed (not blocked by ratchet)
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _proof(2), _complianceInputs(0, alice, t0), PROVIDER_SET_HASH);
        vm.stopPrank();

        assertEq(oracle.lastProofTimestamp(alice, 0), t0);
    }

    // -------------------------------------------------------------------------
    // Backward proofs rejected
    // -------------------------------------------------------------------------

    function test_ratchet_rejectsOlderProof() public {
        uint256 t0 = block.timestamp;
        // First proof at now: ratchet records t0
        vm.startPrank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _proof(1), _complianceInputs(0, alice, t0), PROVIDER_SET_HASH);

        vm.warp(t0 + 200);
        // Submit older proof (timestamp t0 - 50 is older than the recorded ratchet)
        bytes memory olderInputs = _complianceInputs(0, alice, t0 - 50);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.ProofTimestampNotMonotonic.selector, t0 - 50, t0));
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _proof(2), olderInputs, PROVIDER_SET_HASH);
        vm.stopPrank();
    }

    function test_ratchet_rejectsBackwardEvenWithinMaxAge() public {
        // MAX_PROOF_AGE is 1h. Ratchet must reject proofs that are older than the last one
        // even if both are still within the absolute MAX_PROOF_AGE window from now.
        uint256 t0 = block.timestamp;
        vm.warp(t0 + 1800);
        vm.startPrank(alice);
        // Record ratchet at t0 + 1800 (== now)
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _proof(1), _complianceInputs(0, alice, t0 + 1800), PROVIDER_SET_HASH
        );

        vm.warp(t0 + 1900);
        // Older proof at t0 + 1700 is in the past (within MAX_PROOF_AGE) but behind the ratchet.
        bytes memory olderInputs = _complianceInputs(0, alice, t0 + 1700);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPOracle.ProofTimestampNotMonotonic.selector, t0 + 1700, t0 + 1800)
        );
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _proof(2), olderInputs, PROVIDER_SET_HASH);
        vm.stopPrank();
    }

    // -------------------------------------------------------------------------
    // Per-(subject, jurisdiction) isolation
    // -------------------------------------------------------------------------

    function test_ratchet_separateJurisdictions_independent() public {
        // Use EU (0) and UK (2), both permissive jurisdictions; the ratchet test is
        // about per-jurisdiction state isolation and is orthogonal to signed-signals.
        uint256 t0 = block.timestamp;
        vm.warp(t0 + 100);
        vm.startPrank(alice);
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _proof(1), _complianceInputs(0, alice, t0 + 100), PROVIDER_SET_HASH
        );
        // Different jurisdiction; independent ratchet -- earlier proofTimestamp is fine
        oracle.submitCompliance(2, ProofTypes.COMPLIANCE, _proof(2), _complianceInputs(2, alice, t0), PROVIDER_SET_HASH);
        vm.stopPrank();

        assertEq(oracle.lastProofTimestamp(alice, 0), t0 + 100);
        assertEq(oracle.lastProofTimestamp(alice, 2), t0);
    }

    function test_ratchet_separateUsers_independent() public {
        uint256 t0 = block.timestamp;
        vm.warp(t0 + 100);
        vm.prank(alice);
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _proof(1), _complianceInputs(0, alice, t0 + 100), PROVIDER_SET_HASH
        );
        // Bob's ratchet is independent of alice's -- earlier proofTimestamp is fine for bob
        vm.prank(bob);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _proof(2), _complianceInputs(0, bob, t0), PROVIDER_SET_HASH);

        assertEq(oracle.lastProofTimestamp(alice, 0), t0 + 100);
        assertEq(oracle.lastProofTimestamp(bob, 0), t0);
    }

    // -------------------------------------------------------------------------
    // Initial state
    // -------------------------------------------------------------------------

    function test_ratchet_initialState_isZero() public view {
        assertEq(oracle.lastProofTimestamp(alice, 0), 0);
    }

    function test_ratchet_firstSubmissionRecordsTimestamp() public {
        uint256 t0 = block.timestamp;
        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _proof(1), _complianceInputs(0, alice, t0), PROVIDER_SET_HASH);
        assertEq(oracle.lastProofTimestamp(alice, 0), t0);
    }
}
