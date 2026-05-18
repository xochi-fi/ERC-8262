// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC8262Oracle} from "../src/ERC8262Oracle.sol";
import {ERC8262Verifier} from "../src/ERC8262Verifier.sol";
import {AccessControl} from "../src/libraries/AccessControl.sol";
import {Ownable2Step} from "../src/libraries/Ownable2Step.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";

contract AccessControlTest is Test {
    ERC8262Oracle internal oracle;
    ERC8262Verifier internal verifier;

    address internal owner = makeAddr("owner");
    address internal guardian = makeAddr("guardian");
    address internal registrar = makeAddr("registrar");
    address internal config = makeAddr("config");
    address internal stranger = makeAddr("stranger");

    bytes32 internal constant INITIAL_CONFIG = keccak256("initial-config");

    // Cached role hashes (calling GUARDIAN inline consumes vm.prank)
    bytes32 internal GUARDIAN;
    bytes32 internal REGISTRAR;
    bytes32 internal CONFIG;

    function _defaultProviders() internal pure returns (uint256[] memory ps) {
        ps = new uint256[](1);
        ps[0] = 1;
    }

    function setUp() public {
        verifier = new ERC8262Verifier(owner);
        oracle = new ERC8262Oracle(address(verifier), owner, INITIAL_CONFIG, _defaultProviders());
        GUARDIAN = keccak256("GUARDIAN");
        REGISTRAR = keccak256("REGISTRAR");
        CONFIG = keccak256("CONFIG");
    }

    // -------------------------------------------------------------------------
    // Owner has implicit roles
    // -------------------------------------------------------------------------

    function test_owner_implicitlyHoldsAllRoles() public view {
        assertTrue(oracle.hasRole(GUARDIAN, owner));
        assertTrue(oracle.hasRole(REGISTRAR, owner));
        assertTrue(oracle.hasRole(CONFIG, owner));
        assertTrue(verifier.hasRole(GUARDIAN, owner));
    }

    function test_strangerHasNoRoles() public view {
        assertFalse(oracle.hasRole(GUARDIAN, stranger));
        assertFalse(oracle.hasRole(REGISTRAR, stranger));
        assertFalse(oracle.hasRole(CONFIG, stranger));
    }

    // -------------------------------------------------------------------------
    // grantRole / revokeRole
    // -------------------------------------------------------------------------

    function test_grantRole_setsRole() public {
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit AccessControl.RoleGranted(GUARDIAN, guardian);
        oracle.grantRole(GUARDIAN, guardian);
        assertTrue(oracle.hasRole(GUARDIAN, guardian));
    }

    function test_grantRole_revert_notOwner() public {
        vm.prank(stranger);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        oracle.grantRole(GUARDIAN, stranger);
    }

    function test_grantRole_revert_zeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        oracle.grantRole(GUARDIAN, address(0));
    }

    function test_grantRole_revert_invalidRole() public {
        bytes32 fakeRole = keccak256("FAKE");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AccessControl.InvalidRole.selector, fakeRole));
        oracle.grantRole(fakeRole, guardian);
    }

    function test_grantRole_revert_alreadyGranted() public {
        vm.startPrank(owner);
        oracle.grantRole(GUARDIAN, guardian);
        vm.expectRevert(abi.encodeWithSelector(AccessControl.AlreadyHasRole.selector, GUARDIAN, guardian));
        oracle.grantRole(GUARDIAN, guardian);
        vm.stopPrank();
    }

    function test_revokeRole_clearsRole() public {
        vm.startPrank(owner);
        oracle.grantRole(GUARDIAN, guardian);
        vm.expectEmit(true, true, false, false);
        emit AccessControl.RoleRevoked(GUARDIAN, guardian);
        oracle.revokeRole(GUARDIAN, guardian);
        vm.stopPrank();
        assertFalse(oracle.hasRole(GUARDIAN, guardian));
    }

    function test_revokeRole_revert_notOwner() public {
        vm.startPrank(owner);
        oracle.grantRole(GUARDIAN, guardian);
        vm.stopPrank();

        vm.prank(stranger);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        oracle.revokeRole(GUARDIAN, guardian);
    }

    function test_revokeRole_revert_doesNotHaveRole() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(AccessControl.DoesNotHaveRole.selector, GUARDIAN, guardian));
        oracle.revokeRole(GUARDIAN, guardian);
    }

    // -------------------------------------------------------------------------
    // Role enforcement: GUARDIAN can pause, others cannot
    // -------------------------------------------------------------------------

    function test_guardian_canPause() public {
        vm.prank(owner);
        oracle.grantRole(GUARDIAN, guardian);

        vm.prank(guardian);
        oracle.pause();
        assertTrue(oracle.paused());
    }

    function test_registrar_cannotPause() public {
        vm.prank(owner);
        oracle.grantRole(REGISTRAR, registrar);

        vm.prank(registrar);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.pause();
    }

    function test_config_cannotPause() public {
        vm.prank(owner);
        oracle.grantRole(CONFIG, config);

        vm.prank(config);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.pause();
    }

    // -------------------------------------------------------------------------
    // Role enforcement: REGISTRAR can manage merkle roots, others cannot
    // -------------------------------------------------------------------------

    function test_registrar_canRegisterMerkleRoot() public {
        vm.prank(owner);
        oracle.grantRole(REGISTRAR, registrar);

        vm.prank(registrar);
        oracle.registerMerkleRoot(keccak256("root"));
        assertTrue(oracle.isValidMerkleRoot(keccak256("root")));
    }

    function test_guardian_cannotRegisterMerkleRoot() public {
        vm.prank(owner);
        oracle.grantRole(GUARDIAN, guardian);

        vm.prank(guardian);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.registerMerkleRoot(keccak256("root"));
    }

    // -------------------------------------------------------------------------
    // Role enforcement: CONFIG can update provider config, others cannot
    // -------------------------------------------------------------------------

    function test_config_canUpdateProviderConfig() public {
        vm.prank(owner);
        oracle.grantRole(CONFIG, config);

        bytes32 newHash = keccak256("v2");
        vm.prank(config);
        oracle.updateProviderConfig(newHash, "ipfs://v2", _defaultProviders());
        assertEq(oracle.providerConfigHash(), newHash);
    }

    function test_guardian_cannotUpdateProviderConfig() public {
        vm.prank(owner);
        oracle.grantRole(GUARDIAN, guardian);

        vm.prank(guardian);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.updateProviderConfig(keccak256("v2"), "", _defaultProviders());
    }

    // -------------------------------------------------------------------------
    // Verifier: GUARDIAN can revoke versions immediately
    // -------------------------------------------------------------------------

    function test_verifier_guardian_canRevokeVersion() public {
        // Build a 2-version history so we can revoke v1
        StubVerifier v1 = new StubVerifier();
        StubVerifier v2 = new StubVerifier();

        vm.startPrank(owner);
        verifier.setVerifierInitial(ProofTypes.COMPLIANCE, address(v1));
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, address(v2), address(v2).codehash);
        vm.warp(block.timestamp + 24 hours);
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
        verifier.grantRole(GUARDIAN, guardian);
        vm.stopPrank();

        vm.prank(guardian);
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);
        assertTrue(verifier.isVersionRevoked(ProofTypes.COMPLIANCE, 1));
    }

    function test_verifier_config_cannotImmediatelyRevoke() public {
        // CONFIG must use the proposeVersionRevocation path (timelocked); only GUARDIAN
        // gets the immediate emergency path.
        StubVerifier v1 = new StubVerifier();
        StubVerifier v2 = new StubVerifier();

        vm.startPrank(owner);
        verifier.setVerifierInitial(ProofTypes.COMPLIANCE, address(v1));
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, address(v2), address(v2).codehash);
        vm.warp(block.timestamp + 24 hours);
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
        verifier.grantRole(CONFIG, config);
        vm.stopPrank();

        vm.prank(config);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        verifier.revokeVerifierVersion(ProofTypes.COMPLIANCE, 1);
    }

    function test_verifier_config_canScheduleRevocation() public {
        StubVerifier v1 = new StubVerifier();
        StubVerifier v2 = new StubVerifier();

        vm.startPrank(owner);
        verifier.setVerifierInitial(ProofTypes.COMPLIANCE, address(v1));
        verifier.proposeVerifier(ProofTypes.COMPLIANCE, address(v2), address(v2).codehash);
        vm.warp(block.timestamp + 24 hours);
        verifier.executeVerifierUpdate(ProofTypes.COMPLIANCE);
        verifier.grantRole(CONFIG, config);
        vm.stopPrank();

        vm.prank(config);
        verifier.proposeVersionRevocation(ProofTypes.COMPLIANCE, 1);
        assertGt(verifier.getPendingRevocation(ProofTypes.COMPLIANCE, 1), 0);
    }
}

contract StubVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}
