// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ERC8262Oracle} from "../src/ERC8262Oracle.sol";

/// @title Bootstrap -- Post-deployment registry seeding for Xochi ZKP
/// @notice Registers the initial set of provider publishers, reporting thresholds,
///         and merkle roots that the oracle needs to accept production proofs.
///
///         Run this AFTER `Deploy.s.sol` and AFTER the timelock has accepted ownership
///         (if USE_TIMELOCK=true was set). When timelock-owned, this script will fail
///         with `Unauthorized` -- the operations must instead be scheduled through the
///         timelock by the proposer multisig.
///
/// Usage:
///   forge script script/Bootstrap.s.sol --rpc-url $RPC_URL --broadcast
///
/// Required env vars:
///   PRIVATE_KEY          -- key controlling the oracle owner role at the time of running
///                           (deployer EOA pre-timelock, or timelock proposer post-timelock)
///   ORACLE_ADDRESS       -- deployed oracle address
///
/// Optional env vars (control which sections run):
///   PROVIDERS_JSON       -- JSON array of {providerId, publisher} to register
///                           e.g., '[{"providerId":42,"publisher":"0xAB..."}]'
///   REPORTING_THRESHOLDS -- comma-separated list of u64 thresholds to register
///                           e.g., "10000,5000"
///   MERKLE_ROOTS         -- comma-separated list of merkle roots (bytes32 hex) to register
///                           e.g., "0xabcd...,0x1234..."
///   SIGNER_PUBKEY_HASHES -- comma-separated list of signer pubkey hashes (bytes32 hex)
///                           authorized for COMPLIANCE_SIGNED / RISK_SCORE_SIGNED proofs.
///                           e.g., "0xabcd...,0x1234..."
///
/// Examples:
///   ORACLE_ADDRESS=0x... REPORTING_THRESHOLDS=10000 forge script script/Bootstrap.s.sol --broadcast
contract Bootstrap is Script {
    function run() public {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address oracleAddr = vm.envAddress("ORACLE_ADDRESS");
        ERC8262Oracle oracle = ERC8262Oracle(oracleAddr);

        console.log("Bootstrap target:", oracleAddr);
        console.log("Caller:", vm.addr(deployerKey));
        console.log("Oracle owner:", oracle.owner());

        vm.startBroadcast(deployerKey);

        _bootstrapProviders(oracle);
        _bootstrapReportingThresholds(oracle);
        _bootstrapMerkleRoots(oracle);
        _bootstrapSignerPubkeyHashes(oracle);

        vm.stopBroadcast();

        console.log("Bootstrap complete.");
    }

    /// @dev Register provider publishers from a JSON env var.
    ///      Format: '[{"providerId":42,"publisher":"0xAB..."}, ...]'
    function _bootstrapProviders(ERC8262Oracle oracle) internal {
        string memory json = vm.envOr("PROVIDERS_JSON", string(""));
        if (bytes(json).length == 0) {
            console.log("No PROVIDERS_JSON; skipping provider publisher registration.");
            return;
        }

        // forge-std parseJson returns abi-encoded data; we expect an array
        bytes memory raw = vm.parseJson(json);
        // Decode as a tuple array of (uint256 providerId, address publisher)
        (uint256[] memory providerIds, address[] memory publishers) = abi.decode(raw, (uint256[], address[]));
        require(providerIds.length == publishers.length, "PROVIDERS_JSON shape mismatch");

        for (uint256 i; i < providerIds.length; i++) {
            oracle.setProviderPublisher(providerIds[i], publishers[i]);
            console.log("Set provider publisher:");
            console.log("  providerId:", providerIds[i]);
            console.log("  publisher:", publishers[i]);
        }
    }

    /// @dev Register reporting thresholds from a comma-separated env var.
    function _bootstrapReportingThresholds(ERC8262Oracle oracle) internal {
        string memory raw = vm.envOr("REPORTING_THRESHOLDS", string(""));
        if (bytes(raw).length == 0) {
            console.log("No REPORTING_THRESHOLDS; skipping reporting threshold registration.");
            return;
        }
        string[] memory parts = vm.split(raw, ",");
        for (uint256 i; i < parts.length; i++) {
            uint256 threshold = vm.parseUint(parts[i]);
            oracle.registerReportingThreshold(bytes32(threshold));
            console.log("Registered reporting threshold:", threshold);
        }
    }

    /// @dev Register merkle roots from a comma-separated env var of bytes32 hex strings.
    function _bootstrapMerkleRoots(ERC8262Oracle oracle) internal {
        string memory raw = vm.envOr("MERKLE_ROOTS", string(""));
        if (bytes(raw).length == 0) {
            console.log("No MERKLE_ROOTS; skipping merkle root registration.");
            return;
        }
        string[] memory parts = vm.split(raw, ",");
        for (uint256 i; i < parts.length; i++) {
            bytes32 root = vm.parseBytes32(parts[i]);
            oracle.registerMerkleRoot(root);
            console.log("Registered merkle root:");
            console.logBytes32(root);
        }
    }

    /// @dev Register signer pubkey hashes for provider-signed-signals proofs (audit I-1).
    function _bootstrapSignerPubkeyHashes(ERC8262Oracle oracle) internal {
        string memory raw = vm.envOr("SIGNER_PUBKEY_HASHES", string(""));
        if (bytes(raw).length == 0) {
            console.log("No SIGNER_PUBKEY_HASHES; skipping signer pubkey hash registration.");
            return;
        }
        string[] memory parts = vm.split(raw, ",");
        for (uint256 i; i < parts.length; i++) {
            bytes32 hash = vm.parseBytes32(parts[i]);
            oracle.registerSignerPubkeyHash(hash);
            console.log("Registered signer pubkey hash:");
            console.logBytes32(hash);
        }
    }
}
