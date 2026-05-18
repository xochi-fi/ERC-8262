// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ERC8262Verifier} from "../src/ERC8262Verifier.sol";
import {ERC8262Oracle} from "../src/ERC8262Oracle.sol";
import {Timelock} from "../src/Timelock.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";
// Force generated verifiers into the script's build graph so vm.getCode can find them.
// `forge script` only builds files reachable from the script's imports.
import {ComplianceVerifier} from "../src/generated/compliance_verifier.sol";
import {ComplianceSignedVerifier} from "../src/generated/compliance_signed_verifier.sol";
import {ComplianceMultiSignedVerifier} from "../src/generated/compliance_multi_signed_verifier.sol";
import {RiskScoreVerifier} from "../src/generated/risk_score_verifier.sol";
import {RiskScoreSignedVerifier} from "../src/generated/risk_score_signed_verifier.sol";
import {PatternVerifier} from "../src/generated/pattern_verifier.sol";
import {AttestationVerifier} from "../src/generated/attestation_verifier.sol";
import {MembershipVerifier} from "../src/generated/membership_verifier.sol";
import {NonMembershipVerifier} from "../src/generated/non_membership_verifier.sol";

/// @title Deploy -- Deployment script for Xochi ZKP contracts
/// @notice Deploys the verifier router, oracle, and all 6 generated UltraHonk
///         verifier contracts, then registers each verifier with the router.
///         Optionally deploys Timelock and transfers ownership to it.
///
/// Usage:
///   forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
///
/// Required env vars:
///   PRIVATE_KEY          -- deployer private key
///   INITIAL_CONFIG_HASH  -- initial provider weight config hash (must be non-zero)
///   INITIAL_PROVIDER_IDS -- comma-separated uint256 provider IDs whose weights
///                           are committed-to by INITIAL_CONFIG_HASH. The
///                           expansion is registered atomically with the config
///                           in the Oracle constructor (audit F-2). Must be
///                           non-empty; zero IDs are rejected.
///
/// Optional env vars:
///   DEPLOY_SALT          -- CREATE2 salt prefix (default: "xochi-v1")
///   USE_TIMELOCK         -- if "true", deploy Timelock and transfer ownership to it
///                           (recommended for production deployments per docs/THREAT_MODEL.md)
///   TIMELOCK_PROPOSER    -- multisig EOA that schedules timelock ops (required if USE_TIMELOCK=true)
///   TIMELOCK_GUARDIAN    -- guardian EOA that can cancel scheduled ops (optional)
///
/// Post-deployment steps (NOT in this script -- see Bootstrap.s.sol):
///   - Register provider publishers via Oracle.setProviderPublisher
///   - Register reporting thresholds via Oracle.registerReportingThreshold (per jurisdiction)
///   - Register initial merkle roots via Oracle.registerMerkleRoot (sanctions / whitelist sets)
///
/// If USE_TIMELOCK=true, all post-deployment admin operations MUST go through the timelock.
contract Deploy is Script {
    function run() public {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);
        bytes32 configHash = vm.envBytes32("INITIAL_CONFIG_HASH");
        uint256[] memory providerIds = vm.envUint("INITIAL_PROVIDER_IDS", ",");
        bytes32 baseSalt = vm.envOr("DEPLOY_SALT", bytes32("xochi-v1"));
        bool useTimelock = vm.envOr("USE_TIMELOCK", false);

        require(configHash != bytes32(0), "INITIAL_CONFIG_HASH must be non-zero");
        require(providerIds.length > 0, "INITIAL_PROVIDER_IDS must be non-empty");

        console.log("Deployer:", deployer);
        console.log("Initial config hash:");
        console.logBytes32(configHash);
        console.log("Initial provider IDs:");
        for (uint256 i; i < providerIds.length; i++) {
            console.log("  -", providerIds[i]);
        }
        console.log("Use timelock:", useTimelock);

        vm.startBroadcast(deployerKey);

        // 1. Deploy the verifier router (deterministic via CREATE2)
        ERC8262Verifier verifier = new ERC8262Verifier{salt: baseSalt}(deployer);
        console.log("ERC8262Verifier:", address(verifier));

        // 2. Deploy the oracle (deterministic via CREATE2). The provider expansion
        //    for `configHash` is written atomically in the constructor so denylist
        //    enforcement is in effect from block one (audit F-2).
        ERC8262Oracle oracle = new ERC8262Oracle{salt: keccak256(abi.encodePacked(baseSalt, "oracle"))}(
            address(verifier), deployer, configHash, providerIds
        );
        console.log("ERC8262Oracle:", address(oracle));

        // 3. Deploy generated UltraHonk verifiers and register them.
        //    Factored into a helper so run()'s local-variable count stays
        //    inside the EVM stack budget (audit F-1 hardening: previously the
        //    inline form pushed run() over the limit once post-conditions
        //    were added).
        _deployAndRegisterVerifiers(verifier, baseSalt);

        // 4. Optional: deploy Timelock and transfer ownership to it.
        //    For production deployments, this is strongly recommended -- the timelock
        //    enforces the 24h / 6h delays documented in docs/THREAT_MODEL.md.
        if (useTimelock) {
            _setupTimelock(verifier, oracle, baseSalt);
        }

        vm.stopBroadcast();

        // ─── Post-condition assertions (audit F-1) ──────────────────────────
        //
        // Validate the deployment ended up in the expected state. Forge
        // scripts halt on revert, so any failed assertion here aborts the
        // whole run -- preventing a partial-state deployment from being
        // declared successful. Run before the deployer hands off.
        _assertPostConditions(verifier, oracle, useTimelock, deployer, providerIds.length);
    }

    /// @dev Deploy each generated UltraHonk verifier and register it with the
    ///      router. Direct `new` (not vm.getCode) avoids the artifact-lookup
    ///      quirk where `forge script`'s build set differs from `forge test`'s.
    function _deployAndRegisterVerifiers(ERC8262Verifier verifier, bytes32 baseSalt) internal {
        address v;
        v = address(new ComplianceVerifier{salt: keccak256(abi.encodePacked(baseSalt, "ComplianceVerifier"))}());
        verifier.setVerifierInitial(ProofTypes.COMPLIANCE, v);
        console.log("  ComplianceVerifier:", v);

        v = address(new RiskScoreVerifier{salt: keccak256(abi.encodePacked(baseSalt, "RiskScoreVerifier"))}());
        verifier.setVerifierInitial(ProofTypes.RISK_SCORE, v);
        console.log("  RiskScoreVerifier:", v);

        v = address(new PatternVerifier{salt: keccak256(abi.encodePacked(baseSalt, "PatternVerifier"))}());
        verifier.setVerifierInitial(ProofTypes.PATTERN, v);
        console.log("  PatternVerifier:", v);

        v = address(new AttestationVerifier{salt: keccak256(abi.encodePacked(baseSalt, "AttestationVerifier"))}());
        verifier.setVerifierInitial(ProofTypes.ATTESTATION, v);
        console.log("  AttestationVerifier:", v);

        v = address(new MembershipVerifier{salt: keccak256(abi.encodePacked(baseSalt, "MembershipVerifier"))}());
        verifier.setVerifierInitial(ProofTypes.MEMBERSHIP, v);
        console.log("  MembershipVerifier:", v);

        v = address(new NonMembershipVerifier{salt: keccak256(abi.encodePacked(baseSalt, "NonMembershipVerifier"))}());
        verifier.setVerifierInitial(ProofTypes.NON_MEMBERSHIP, v);
        console.log("  NonMembershipVerifier:", v);

        // Provider-signed variants close audit finding I-1. Strict-mode jurisdictions
        // (US BSA, Singapore) reject the unsigned siblings; permissive jurisdictions
        // accept either. See JurisdictionConfig.requireSignedSignals.
        v = address(
            new ComplianceSignedVerifier{salt: keccak256(abi.encodePacked(baseSalt, "ComplianceSignedVerifier"))}()
        );
        verifier.setVerifierInitial(ProofTypes.COMPLIANCE_SIGNED, v);
        console.log("  ComplianceSignedVerifier:", v);

        v = address(
            new RiskScoreSignedVerifier{salt: keccak256(abi.encodePacked(baseSalt, "RiskScoreSignedVerifier"))}()
        );
        verifier.setVerifierInitial(ProofTypes.RISK_SCORE_SIGNED, v);
        console.log("  RiskScoreSignedVerifier:", v);

        // Multi-provider signed variant: M-of-N quorum across up to 5 registered signers.
        // Stricter jurisdictions (US, SG) require minMultiProviderThreshold >= 2.
        v = address(
            new ComplianceMultiSignedVerifier{
                salt: keccak256(abi.encodePacked(baseSalt, "ComplianceMultiSignedVerifier"))
            }()
        );
        verifier.setVerifierInitial(ProofTypes.COMPLIANCE_MULTI_SIGNED, v);
        console.log("  ComplianceMultiSignedVerifier:", v);
    }

    /// @dev Deploy Timelock and start the two-step ownership transfer.
    ///      The proposer must accept via the standard schedule + execute path
    ///      (audit F-5 closure).
    function _setupTimelock(ERC8262Verifier verifier, ERC8262Oracle oracle, bytes32 baseSalt) internal {
        address proposer = vm.envAddress("TIMELOCK_PROPOSER");
        address guardian = vm.envOr("TIMELOCK_GUARDIAN", address(0));
        require(proposer != address(0), "TIMELOCK_PROPOSER must be set when USE_TIMELOCK=true");

        Timelock timelock = new Timelock{salt: keccak256(abi.encodePacked(baseSalt, "timelock"))}(proposer, guardian);
        console.log("Timelock:", address(timelock));
        console.log("  proposer:", proposer);
        console.log("  guardian:", guardian);

        verifier.transferOwnership(address(timelock));
        oracle.transferOwnership(address(timelock));
        console.log("Ownership transfer initiated. Proposer accepts via timelock schedule+execute:");
        console.log("  data = abi.encodeWithSignature(\"acceptOwnership()\")");
        console.log("  - timelock.schedule(verifier, 0, data, salt)  then execute after 24h");
        console.log("  - timelock.schedule(oracle,   0, data, salt)  then execute after 24h");
        console.log("Must complete within Ownable2Step's 48h acceptance window.");
    }

    /// @dev Verifies every invariant the deploy flow is supposed to establish.
    ///      Reverts with a descriptive message if any check fails.
    function _assertPostConditions(
        ERC8262Verifier verifier,
        ERC8262Oracle oracle,
        bool useTimelock,
        address deployer,
        uint256 expectedProviderCount
    ) internal view {
        // 1. Oracle's immutable verifier reference matches what we deployed.
        require(address(oracle.verifier()) == address(verifier), "post-deploy: oracle.verifier mismatch");

        // 2. Every proof type 0x01..0x09 has a non-zero verifier registered.
        uint8[9] memory ptypes = [
            ProofTypes.COMPLIANCE,
            ProofTypes.RISK_SCORE,
            ProofTypes.PATTERN,
            ProofTypes.ATTESTATION,
            ProofTypes.MEMBERSHIP,
            ProofTypes.NON_MEMBERSHIP,
            ProofTypes.COMPLIANCE_SIGNED,
            ProofTypes.RISK_SCORE_SIGNED,
            ProofTypes.COMPLIANCE_MULTI_SIGNED
        ];
        for (uint256 i; i < ptypes.length; i++) {
            address v = verifier.getVerifier(ptypes[i]);
            require(v != address(0), "post-deploy: verifier not set for some proof type");
            require(v.code.length > 0, "post-deploy: verifier address has no code");
        }

        // 3. Initial provider expansion is registered for the active config
        //    (audit F-2 closure: the constructor wrote it atomically).
        uint256[] memory expansion = oracle.getProviderConfigExpansion(oracle.providerConfigHash());
        require(expansion.length == expectedProviderCount, "post-deploy: provider expansion length mismatch");

        // 4. Ownership state matches the requested deployment shape.
        if (useTimelock) {
            // After transferOwnership, owner is still the deployer until the
            // timelock accepts; pendingOwner must be the timelock for both.
            require(verifier.owner() == deployer, "post-deploy: verifier owner not deployer pre-accept");
            require(oracle.owner() == deployer, "post-deploy: oracle owner not deployer pre-accept");
            require(verifier.pendingOwner() != address(0), "post-deploy: verifier pendingOwner unset");
            require(oracle.pendingOwner() != address(0), "post-deploy: oracle pendingOwner unset");
        } else {
            require(verifier.owner() == deployer, "post-deploy: verifier owner mismatch");
            require(oracle.owner() == deployer, "post-deploy: oracle owner mismatch");
            require(verifier.pendingOwner() == address(0), "post-deploy: verifier has stray pendingOwner");
            require(oracle.pendingOwner() == address(0), "post-deploy: oracle has stray pendingOwner");
        }

        console.log("Post-deploy assertions: PASS");
    }
}
