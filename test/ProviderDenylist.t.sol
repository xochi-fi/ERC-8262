// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {XochiZKPOracle} from "../src/XochiZKPOracle.sol";
import {XochiZKPVerifier} from "../src/XochiZKPVerifier.sol";
import {IXochiZKPOracle} from "../src/interfaces/IXochiZKPOracle.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {AccessControl} from "../src/libraries/AccessControl.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";

contract AlwaysPassVerifier is IUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract ProviderDenylistTest is Test {
    XochiZKPOracle internal oracle;
    XochiZKPVerifier internal verifier;
    AlwaysPassVerifier internal stub;

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");

    bytes32 internal constant INITIAL_CONFIG = keccak256("initial-config");
    bytes32 internal constant PROVIDER_SET_HASH = keccak256("providers");
    uint256 internal constant SUMSUB = 1;
    uint256 internal constant CHAINALYSIS = 2;
    uint256 internal constant TRM = 3;

    /// @dev Initial provider expansion registered in the constructor (audit F-2).
    ///      INITIAL_CONFIG commits to {SUMSUB, CHAINALYSIS, TRM} for all tests below.
    function _initialProviders() internal pure returns (uint256[] memory ps) {
        ps = new uint256[](3);
        ps[0] = SUMSUB;
        ps[1] = CHAINALYSIS;
        ps[2] = TRM;
    }

    function setUp() public {
        verifier = new XochiZKPVerifier(owner);
        oracle = new XochiZKPOracle(address(verifier), owner, INITIAL_CONFIG, _initialProviders());
        stub = new AlwaysPassVerifier();

        vm.startPrank(owner);
        for (uint8 i = ProofTypes.COMPLIANCE; i <= ProofTypes.NON_MEMBERSHIP; i++) {
            verifier.setVerifierInitial(i, address(stub));
        }
        vm.stopPrank();
    }

    function _complianceInputs(address submitter) internal view returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(0)), // jurisdiction
            PROVIDER_SET_HASH,
            INITIAL_CONFIG,
            bytes32(block.timestamp),
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
    // Atomic constructor + updateProviderConfig expansion (audit F-2)
    // -------------------------------------------------------------------------

    function test_constructor_storesInitialExpansion() public view {
        uint256[] memory stored = oracle.getProviderConfigExpansion(INITIAL_CONFIG);
        assertEq(stored.length, 3);
        assertEq(stored[0], SUMSUB);
        assertEq(stored[1], CHAINALYSIS);
        assertEq(stored[2], TRM);
    }

    function test_constructor_revert_emptyInitialExpansion() public {
        XochiZKPVerifier v = new XochiZKPVerifier(owner);
        uint256[] memory empty = new uint256[](0);
        vm.expectRevert(XochiZKPOracle.EmptyProviderExpansion.selector);
        new XochiZKPOracle(address(v), owner, INITIAL_CONFIG, empty);
    }

    function test_constructor_revert_zeroProviderInInitialExpansion() public {
        XochiZKPVerifier v = new XochiZKPVerifier(owner);
        uint256[] memory bad = new uint256[](2);
        bad[0] = SUMSUB;
        bad[1] = 0;
        vm.expectRevert(XochiZKPOracle.InvalidProviderId.selector);
        new XochiZKPOracle(address(v), owner, INITIAL_CONFIG, bad);
    }

    function test_updateProviderConfig_storesExpansionAtomically() public {
        bytes32 v2 = keccak256("v2");
        uint256[] memory providers = new uint256[](2);
        providers[0] = SUMSUB;
        providers[1] = CHAINALYSIS;

        vm.prank(owner);
        oracle.updateProviderConfig(v2, "ipfs://v2", providers);

        uint256[] memory stored = oracle.getProviderConfigExpansion(v2);
        assertEq(stored.length, 2);
        assertEq(stored[0], SUMSUB);
        assertEq(stored[1], CHAINALYSIS);
    }

    function test_updateProviderConfig_revert_emptyExpansion() public {
        uint256[] memory empty = new uint256[](0);
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.EmptyProviderExpansion.selector);
        oracle.updateProviderConfig(keccak256("v2"), "", empty);
    }

    function test_updateProviderConfig_revert_zeroProviderId() public {
        uint256[] memory bad = new uint256[](2);
        bad[0] = SUMSUB;
        bad[1] = 0;
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.InvalidProviderId.selector);
        oracle.updateProviderConfig(keccak256("v2"), "", bad);
    }

    function test_updateProviderConfig_revert_notConfigRole() public {
        uint256[] memory providers = new uint256[](1);
        providers[0] = SUMSUB;
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.updateProviderConfig(keccak256("v2"), "", providers);
    }

    // -------------------------------------------------------------------------
    // denyProvider / undenyProvider
    // -------------------------------------------------------------------------

    function test_denyProvider_setsState() public {
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit XochiZKPOracle.ProviderDeniedEvent(SUMSUB);
        oracle.denyProvider(SUMSUB);
        assertTrue(oracle.isProviderDenied(SUMSUB));
    }

    function test_denyProvider_revert_zeroId() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.InvalidProviderId.selector);
        oracle.denyProvider(0);
    }

    function test_denyProvider_revert_alreadyDenied() public {
        vm.startPrank(owner);
        oracle.denyProvider(SUMSUB);
        vm.expectRevert(XochiZKPOracle.AlreadyRegistered.selector);
        oracle.denyProvider(SUMSUB);
        vm.stopPrank();
    }

    function test_denyProvider_revert_notGuardian() public {
        vm.prank(alice);
        vm.expectPartialRevert(AccessControl.NotRole.selector);
        oracle.denyProvider(SUMSUB);
    }

    function test_undenyProvider_clearsState() public {
        vm.startPrank(owner);
        oracle.denyProvider(SUMSUB);
        oracle.undenyProvider(SUMSUB);
        vm.stopPrank();
        assertFalse(oracle.isProviderDenied(SUMSUB));
    }

    function test_undenyProvider_revert_notDenied() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.NotRegistered.selector);
        oracle.undenyProvider(SUMSUB);
    }

    // -------------------------------------------------------------------------
    // Compliance proof rejection when config contains denied provider
    // -------------------------------------------------------------------------

    function test_submit_succeeds_whenNoDenials() public {
        // Initial config in setUp committed to {SUMSUB, CHAINALYSIS, TRM} atomically;
        // no denial yet (audit F-2 closure).
        bytes memory proof = _proof(1);
        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(alice), PROVIDER_SET_HASH);
    }

    function test_submit_revertsWhenConfigContainsDeniedProvider() public {
        vm.prank(owner);
        oracle.denyProvider(CHAINALYSIS); // simulate compromise

        bytes memory proof = _proof(1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.ProviderDenied.selector, CHAINALYSIS));
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(alice), PROVIDER_SET_HASH);
    }

    function test_submit_recoversAfterUndeny() public {
        vm.startPrank(owner);
        oracle.denyProvider(SUMSUB);
        oracle.undenyProvider(SUMSUB);
        vm.stopPrank();

        bytes memory proof = _proof(1);
        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(alice), PROVIDER_SET_HASH);
    }

    function test_denial_appliesToAllConfigsContainingProvider() public {
        // Add a second config that also contains SUMSUB. After denyProvider(SUMSUB)
        // both configs are unusable -- audit F-2 closure: every valid config has
        // its expansion on-chain at registration time.
        bytes32 v2 = keccak256("v2");
        uint256[] memory providers2 = new uint256[](2);
        providers2[0] = SUMSUB;
        providers2[1] = CHAINALYSIS;
        vm.startPrank(owner);
        oracle.updateProviderConfig(v2, "ipfs://v2", providers2);
        oracle.denyProvider(SUMSUB);
        vm.stopPrank();

        bytes memory proof = _proof(2);
        bytes memory inputs = abi.encodePacked(
            bytes32(uint256(0)),
            PROVIDER_SET_HASH,
            v2,
            bytes32(block.timestamp),
            bytes32(uint256(1)),
            bytes32(uint256(uint160(alice)))
        );
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.ProviderDenied.selector, SUMSUB));
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, inputs, PROVIDER_SET_HASH);
    }
}
