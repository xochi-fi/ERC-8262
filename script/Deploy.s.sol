// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {XochiZKPVerifier} from "../src/XochiZKPVerifier.sol";
import {XochiZKPOracle} from "../src/XochiZKPOracle.sol";
import {XochiTimelock} from "../src/XochiTimelock.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";
// Force generated verifiers into the script's build graph so vm.getCode can find them.
// `forge script` only builds files reachable from the script's imports.
import {ComplianceVerifier} from "../src/generated/compliance_verifier.sol";
import {RiskScoreVerifier} from "../src/generated/risk_score_verifier.sol";
import {PatternVerifier} from "../src/generated/pattern_verifier.sol";
import {AttestationVerifier} from "../src/generated/attestation_verifier.sol";
import {MembershipVerifier} from "../src/generated/membership_verifier.sol";
import {NonMembershipVerifier} from "../src/generated/non_membership_verifier.sol";

/// @title Deploy -- Deployment script for Xochi ZKP contracts
/// @notice Deploys the verifier router, oracle, and all 6 generated UltraHonk
///         verifier contracts, then registers each verifier with the router.
///         Optionally deploys XochiTimelock and transfers ownership to it.
///
/// Usage:
///   forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
///
/// Required env vars:
///   PRIVATE_KEY          -- deployer private key
///   INITIAL_CONFIG_HASH  -- initial provider weight config hash (must be non-zero)
///
/// Optional env vars:
///   DEPLOY_SALT          -- CREATE2 salt prefix (default: "xochi-v1")
///   USE_TIMELOCK         -- if "true", deploy XochiTimelock and transfer ownership to it
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
        bytes32 baseSalt = vm.envOr("DEPLOY_SALT", bytes32("xochi-v1"));
        bool useTimelock = vm.envOr("USE_TIMELOCK", false);

        require(configHash != bytes32(0), "INITIAL_CONFIG_HASH must be non-zero");

        console.log("Deployer:", deployer);
        console.log("Initial config hash:");
        console.logBytes32(configHash);
        console.log("Use timelock:", useTimelock);

        vm.startBroadcast(deployerKey);

        // 1. Deploy the verifier router (deterministic via CREATE2)
        XochiZKPVerifier verifier = new XochiZKPVerifier{salt: baseSalt}(deployer);
        console.log("XochiZKPVerifier:", address(verifier));

        // 2. Deploy the oracle (deterministic via CREATE2)
        XochiZKPOracle oracle = new XochiZKPOracle{salt: keccak256(abi.encodePacked(baseSalt, "oracle"))}(
            address(verifier), deployer, configHash
        );
        console.log("XochiZKPOracle:", address(oracle));

        // 3. Deploy generated UltraHonk verifiers and register them.
        //    Direct `new` since we import the contract types -- avoids the
        //    vm.getCode artifact-lookup quirk where `forge script`'s build set
        //    differs from `forge test`'s.
        address complianceVerifier =
            address(new ComplianceVerifier{salt: keccak256(abi.encodePacked(baseSalt, "ComplianceVerifier"))}());
        verifier.setVerifierInitial(ProofTypes.COMPLIANCE, complianceVerifier);
        console.log("  ComplianceVerifier:", complianceVerifier);

        address riskScoreVerifier =
            address(new RiskScoreVerifier{salt: keccak256(abi.encodePacked(baseSalt, "RiskScoreVerifier"))}());
        verifier.setVerifierInitial(ProofTypes.RISK_SCORE, riskScoreVerifier);
        console.log("  RiskScoreVerifier:", riskScoreVerifier);

        address patternVerifier =
            address(new PatternVerifier{salt: keccak256(abi.encodePacked(baseSalt, "PatternVerifier"))}());
        verifier.setVerifierInitial(ProofTypes.PATTERN, patternVerifier);
        console.log("  PatternVerifier:", patternVerifier);

        address attestationVerifier =
            address(new AttestationVerifier{salt: keccak256(abi.encodePacked(baseSalt, "AttestationVerifier"))}());
        verifier.setVerifierInitial(ProofTypes.ATTESTATION, attestationVerifier);
        console.log("  AttestationVerifier:", attestationVerifier);

        address membershipVerifier =
            address(new MembershipVerifier{salt: keccak256(abi.encodePacked(baseSalt, "MembershipVerifier"))}());
        verifier.setVerifierInitial(ProofTypes.MEMBERSHIP, membershipVerifier);
        console.log("  MembershipVerifier:", membershipVerifier);

        address nonMembershipVerifier =
            address(new NonMembershipVerifier{salt: keccak256(abi.encodePacked(baseSalt, "NonMembershipVerifier"))}());
        verifier.setVerifierInitial(ProofTypes.NON_MEMBERSHIP, nonMembershipVerifier);
        console.log("  NonMembershipVerifier:", nonMembershipVerifier);

        // 4. Optional: deploy XochiTimelock and transfer ownership to it.
        //    For production deployments, this is strongly recommended -- the timelock
        //    enforces the 24h / 6h delays documented in docs/THREAT_MODEL.md.
        if (useTimelock) {
            address proposer = vm.envAddress("TIMELOCK_PROPOSER");
            address guardian = vm.envOr("TIMELOCK_GUARDIAN", address(0));
            require(proposer != address(0), "TIMELOCK_PROPOSER must be set when USE_TIMELOCK=true");

            XochiTimelock timelock =
                new XochiTimelock{salt: keccak256(abi.encodePacked(baseSalt, "timelock"))}(proposer, guardian);
            console.log("XochiTimelock:", address(timelock));
            console.log("  proposer:", proposer);
            console.log("  guardian:", guardian);

            // Begin two-step ownership transfer to the timelock.
            // The timelock proposer must call XochiTimelock.acceptOwnership(target)
            // for each contract within the 48-hour Ownable2Step deadline.
            verifier.transferOwnership(address(timelock));
            oracle.transferOwnership(address(timelock));
            console.log("Ownership transfer initiated. Proposer must accept within 48h:");
            console.log("  - timelock.acceptOwnership(verifier)");
            console.log("  - timelock.acceptOwnership(oracle)");
        }

        vm.stopBroadcast();
    }
}
