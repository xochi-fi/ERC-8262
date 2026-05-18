// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC8262Verifier} from "../src/ERC8262Verifier.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";

/// @dev Stub verifier whose verdict can be flipped post-construction.
///      `shouldPass = true` simulates a sound verifier; flipping it to `false`
///      simulates a soundness-bug discovery where the verifier should no longer
///      be trusted.
contract IncidentStub is IUltraVerifier {
    bool public shouldPass;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return shouldPass;
    }
}

/// @title Incident_VerifierSoundness -- runbook-as-code for verifier soundness bugs
/// @notice Walks the documented incident response from `docs/THREAT_MODEL.md`:
///         pause -> revoke historical -> propose new verifier -> 24h timelock ->
///         execute -> unpause. Each step asserts the system enters/leaves the
///         expected state. If this test ever fails, the runbook is broken --
///         which is far cheaper to discover here than during a live incident.
/// @dev Audit F-7 closure.
contract IncidentVerifierSoundnessTest is Test {
    ERC8262Verifier internal verifier;
    IncidentStub internal originalVerifier;
    IncidentStub internal replacementVerifier;

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");

    uint8 internal constant PROOF_TYPE = ProofTypes.COMPLIANCE;

    bytes internal constant PROOF_BYTES = "proof-bytes";

    function setUp() public {
        verifier = new ERC8262Verifier(owner);
        originalVerifier = new IncidentStub(true);

        vm.prank(owner);
        verifier.setVerifierInitial(PROOF_TYPE, address(originalVerifier));
    }

    function _validInputs() internal view returns (bytes memory) {
        // COMPLIANCE has 6 logical pubs; the router only validates length, the
        // generated verifier is replaced by the stub which ignores contents.
        return abi.encodePacked(
            bytes32(uint256(0)), // jurisdictionId
            bytes32(uint256(1)), // providerSetHash
            bytes32(uint256(2)), // configHash
            bytes32(block.timestamp), // timestamp
            bytes32(uint256(1)), // meetsThreshold
            bytes32(uint256(uint160(alice))) // submitter
        );
    }

    /// @notice End-to-end soundness-incident response, asserted step by step.
    ///
    ///         1. **Bug detected.** Verifier still passes proofs (alice can verify).
    ///         2. **Pause proof type** (instant, GUARDIAN). Live verification reverts.
    ///         3. **Revoke historical version** (immediate emergency path).
    ///            verifyProofAtVersion(1) reverts; current routing already paused.
    ///         4. **Propose replacement verifier** (CONFIG, starts 24h timelock).
    ///         5. **Warp 24h, execute** (CONFIG). New verifier is now current at version 2.
    ///         6. **Unpause proof type.** Live verification works again under the
    ///            replacement; the revoked version 1 still rejects.
    function test_runbook_endToEnd_pauseRevokeProposeExecuteUnpause() public {
        bytes memory inputs = _validInputs();

        // (1) Sanity: bug not yet detected, verifier accepts
        bool ok = verifier.verifyProof(PROOF_TYPE, PROOF_BYTES, inputs);
        assertTrue(ok, "pre-incident: original verifier should pass");
        assertEq(verifier.getVerifierVersion(PROOF_TYPE), 1);
        assertEq(verifier.getVerifier(PROOF_TYPE), address(originalVerifier));

        // (2) Pause the proof type (instant, GUARDIAN-equivalent via owner)
        vm.prank(owner);
        verifier.pauseProofType(PROOF_TYPE);
        assertTrue(verifier.isProofTypePaused(PROOF_TYPE));

        // Live verification now reverts even though the underlying verifier
        // would still accept -- this is the surgical kill switch.
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.ProofTypePaused.selector, PROOF_TYPE));
        verifier.verifyProof(PROOF_TYPE, PROOF_BYTES, inputs);

        // verifyProofAtVersion is also gated by the per-type pause.
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.ProofTypePaused.selector, PROOF_TYPE));
        verifier.verifyProofAtVersion(PROOF_TYPE, 1, PROOF_BYTES, inputs);

        // (3) Revoke historical version 1 via the immediate emergency path.
        //     The current version (latest = 1) cannot be revoked while it IS
        //     the current; we must propose the replacement first, execute, and
        //     then revoke v1 once it has been demoted to historical. We do
        //     that here -- propose first, execute later, revoke after demotion.
        replacementVerifier = new IncidentStub(true);

        // (4) Propose replacement (CONFIG-equivalent via owner).
        bytes32 replacementCodehash = address(replacementVerifier).codehash;
        vm.prank(owner);
        verifier.proposeVerifier(PROOF_TYPE, address(replacementVerifier), replacementCodehash);
        (address pending, uint256 readyAt, bytes32 pinnedCodehash) = verifier.getPendingVerifier(PROOF_TYPE);
        assertEq(pending, address(replacementVerifier));
        assertEq(readyAt, block.timestamp + 24 hours);
        assertEq(pinnedCodehash, replacementCodehash);

        // (5) Cannot execute before timelock elapses
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.TimelockNotElapsed.selector, PROOF_TYPE, readyAt));
        vm.prank(owner);
        verifier.executeVerifierUpdate(PROOF_TYPE);

        // Warp the full 24h
        vm.warp(readyAt);

        // Execute -- replacement becomes current, v2 is the new latest
        vm.prank(owner);
        verifier.executeVerifierUpdate(PROOF_TYPE);
        assertEq(verifier.getVerifierVersion(PROOF_TYPE), 2);
        assertEq(verifier.getVerifier(PROOF_TYPE), address(replacementVerifier));

        // (6) NOW revoke v1 (it is no longer the current). Use the immediate
        //     path -- the routine 6h-delay path tests the same invariant via a
        //     different code branch and is covered by ERC8262Verifier.t.sol.
        vm.prank(owner);
        verifier.revokeVerifierVersion(PROOF_TYPE, 1);
        assertTrue(verifier.isVersionRevoked(PROOF_TYPE, 1));

        // (7) Unpause and verify the system is back online
        vm.prank(owner);
        verifier.unpauseProofType(PROOF_TYPE);
        assertFalse(verifier.isProofTypePaused(PROOF_TYPE));

        // Live verification works again under the replacement
        bool okPostIncident = verifier.verifyProof(PROOF_TYPE, PROOF_BYTES, inputs);
        assertTrue(okPostIncident, "post-incident: replacement verifier should pass");
        assertEq(verifier.getVerifier(PROOF_TYPE), address(replacementVerifier));

        // Revoked v1 is permanently locked out for retroactive verification
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.VersionRevoked.selector, PROOF_TYPE, 1));
        verifier.verifyProofAtVersion(PROOF_TYPE, 1, PROOF_BYTES, inputs);

        // v2 still works for retroactive verification
        bool okV2 = verifier.verifyProofAtVersion(PROOF_TYPE, 2, PROOF_BYTES, inputs);
        assertTrue(okV2);
    }

    /// @notice The current version cannot be revoked. This guard is what forces
    ///         the runbook ordering above (propose+execute first, then revoke).
    function test_runbook_cannotRevokeCurrentVersion() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ERC8262Verifier.CannotRevokeCurrentVersion.selector, PROOF_TYPE));
        verifier.revokeVerifierVersion(PROOF_TYPE, 1);
    }

    /// @notice Pause is per-proof-type. A bug in one circuit must not block the
    ///         other seven from operating.
    function test_runbook_pauseIsSurgical_otherProofTypesUnaffected() public {
        // Set up a second proof type with its own stub
        IncidentStub otherStub = new IncidentStub(true);
        vm.prank(owner);
        verifier.setVerifierInitial(ProofTypes.RISK_SCORE, address(otherStub));

        // Pause COMPLIANCE
        vm.prank(owner);
        verifier.pauseProofType(PROOF_TYPE);

        // RISK_SCORE still verifies (different layout: 8 logical pubs)
        bytes memory riskInputs = abi.encodePacked(
            bytes32(uint256(1)), // proof_type
            bytes32(uint256(1)), // direction
            bytes32(uint256(1)), // bound_lower
            bytes32(uint256(0)), // bound_upper
            bytes32(uint256(1)), // result
            bytes32(uint256(2)), // config_hash
            bytes32(uint256(3)), // provider_set_hash
            bytes32(uint256(uint160(alice))) // submitter
        );
        bool ok = verifier.verifyProof(ProofTypes.RISK_SCORE, PROOF_BYTES, riskInputs);
        assertTrue(ok, "unaffected proof type should still verify");
    }

    /// @notice The global pause is the broader hammer if multiple proof types
    ///         are simultaneously suspect.
    function test_runbook_globalPauseStopsAllProofTypes() public {
        IncidentStub otherStub = new IncidentStub(true);
        vm.prank(owner);
        verifier.setVerifierInitial(ProofTypes.RISK_SCORE, address(otherStub));

        vm.prank(owner);
        verifier.pause();
        assertTrue(verifier.paused());

        // Both proof types now revert at the global pause
        vm.expectRevert();
        verifier.verifyProof(PROOF_TYPE, PROOF_BYTES, _validInputs());

        bytes memory riskInputs = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(1)),
            bytes32(uint256(1)),
            bytes32(uint256(0)),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(uint160(alice)))
        );
        vm.expectRevert();
        verifier.verifyProof(ProofTypes.RISK_SCORE, PROOF_BYTES, riskInputs);

        // Unpause restores both
        vm.prank(owner);
        verifier.unpause();
        assertFalse(verifier.paused());

        bool ok = verifier.verifyProof(PROOF_TYPE, PROOF_BYTES, _validInputs());
        assertTrue(ok);
    }
}
