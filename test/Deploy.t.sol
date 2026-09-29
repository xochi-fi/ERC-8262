// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {ERC8262Verifier} from "../src/ERC8262Verifier.sol";
import {ERC8262Oracle} from "../src/ERC8262Oracle.sol";
import {Timelock} from "../src/Timelock.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";

/// @notice USE_TIMELOCK deploy: guardian pauses both contracts instantly, before and after handoff.
contract DeployTimelockTest is Test {
    uint256 internal constant DEPLOYER_KEY = 0xD3; // arbitrary test key
    address internal proposer = makeAddr("proposer");
    address internal guardian = makeAddr("guardian");

    ERC8262Verifier internal verifier;
    ERC8262Oracle internal oracle;
    Timelock internal timelock;

    function setUp() public {
        vm.setEnv("PRIVATE_KEY", vm.toString(DEPLOYER_KEY));
        vm.setEnv("INITIAL_CONFIG_HASH", vm.toString(keccak256("config")));
        vm.setEnv("INITIAL_PROVIDER_IDS", "1,2,3");
        vm.setEnv("USE_TIMELOCK", "true");
        vm.setEnv("TIMELOCK_PROPOSER", vm.toString(proposer));
        vm.setEnv("GUARDIAN_ADDRESS", vm.toString(guardian));

        vm.recordLogs();
        new Deploy().run();

        // Recover deployed addresses from the ownership-transfer events.
        (address v, address o) = _findOwnables();
        verifier = ERC8262Verifier(v);
        oracle = ERC8262Oracle(o);
        timelock = Timelock(payable(verifier.pendingOwner()));
    }

    /// @dev Deploy emits OwnershipTransferStarted for the verifier, then the oracle.
    function _findOwnables() internal view returns (address v, address o) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 sig = keccak256("OwnershipTransferStarted(address,address)");
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].topics.length == 0 || logs[i].topics[0] != sig) continue;
            if (v == address(0)) v = logs[i].emitter;
            else if (o == address(0)) o = logs[i].emitter;
        }
        require(v != address(0) && o != address(0), "ownables not found");
    }

    function _assertGuardianPausesImmediately() internal {
        vm.startPrank(guardian);
        oracle.pause();
        oracle.pauseProofType(ProofTypes.COMPLIANCE);
        verifier.pause();
        verifier.pauseProofType(ProofTypes.COMPLIANCE);
        vm.stopPrank();
        assertTrue(oracle.paused());
        assertTrue(verifier.paused());
    }

    function test_guardianCanPauseRightAfterDeploy() public {
        _assertGuardianPausesImmediately();
    }

    function test_guardianCanPauseAfterTimelockAcceptsOwnership() public {
        bytes memory data = abi.encodeWithSignature("acceptOwnership()");
        vm.startPrank(proposer);
        timelock.schedule(address(verifier), 0, data, bytes32(0));
        timelock.schedule(address(oracle), 0, data, bytes32(0));
        vm.stopPrank();
        vm.warp(block.timestamp + timelock.HIGH_DELAY());
        timelock.execute(address(verifier), 0, data, bytes32(0));
        timelock.execute(address(oracle), 0, data, bytes32(0));
        assertEq(verifier.owner(), address(timelock));
        assertEq(oracle.owner(), address(timelock));

        _assertGuardianPausesImmediately();
    }

    function test_revertsWhenGuardianUnset() public {
        vm.setEnv("GUARDIAN_ADDRESS", vm.toString(address(0)));
        vm.setEnv("DEPLOY_SALT", vm.toString(bytes32("other-salt")));
        Deploy d = new Deploy();
        vm.expectRevert(bytes("GUARDIAN_ADDRESS must be set when USE_TIMELOCK=true"));
        d.run();
    }
}
