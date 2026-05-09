// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SettlementRegistry} from "../src/SettlementRegistry.sol";
import {ISettlementRegistry} from "../src/interfaces/ISettlementRegistry.sol";
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

contract SettlementRegistryTest is Test {
    SettlementRegistry internal registry;
    XochiZKPOracle internal oracle;
    XochiZKPVerifier internal verifier;
    AlwaysPassVerifier internal stubVerifier;

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    bytes32 internal constant INITIAL_CONFIG = keccak256("initial-config");
    bytes32 internal constant DEFAULT_PROVIDER_SET_HASH = bytes32(uint256(0xaabb));

    function _defaultProviders() internal pure returns (uint256[] memory ps) {
        ps = new uint256[](1);
        ps[0] = 1;
    }

    function setUp() public {
        verifier = new XochiZKPVerifier(owner);
        oracle = new XochiZKPOracle(address(verifier), owner, INITIAL_CONFIG, _defaultProviders());

        stubVerifier = new AlwaysPassVerifier();
        vm.startPrank(owner);
        for (uint8 i = ProofTypes.COMPLIANCE; i <= ProofTypes.NON_MEMBERSHIP; i++) {
            verifier.setVerifierInitial(i, address(stubVerifier));
        }
        oracle.registerReportingThreshold(bytes32(uint256(10000)));
        vm.stopPrank();

        registry = new SettlementRegistry(address(oracle));
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    function test_constructor_setsOracle() public view {
        assertEq(address(registry.oracle()), address(oracle));
    }

    function test_constructor_revert_zeroAddress() public {
        vm.expectRevert(SettlementRegistry.ZeroAddress.selector);
        new SettlementRegistry(address(0));
    }

    // -------------------------------------------------------------------------
    // registerTrade
    // -------------------------------------------------------------------------

    function test_registerTrade_createsSettlement() public {
        bytes32 tradeId = keccak256("trade-1");

        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 3);

        ISettlementRegistry.Settlement memory s = registry.getSettlement(tradeId);
        assertEq(s.tradeId, tradeId);
        assertEq(s.subject, alice);
        assertEq(s.jurisdictionId, 0);
        assertEq(s.subTradeCount, 3);
        assertEq(s.settledCount, 0);
        assertEq(s.createdAt, block.timestamp);
        assertEq(s.expiresAt, block.timestamp + 7 days);
        assertFalse(s.finalized);
    }

    function test_registerTrade_emitsEvent() public {
        bytes32 tradeId = keccak256("trade-1");

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit ISettlementRegistry.TradeRegistered(tradeId, alice, 0, 3);
        registry.registerTrade(tradeId, 0, 3);
    }

    function test_registerTrade_revert_duplicate() public {
        bytes32 tradeId = keccak256("trade-1");

        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 3);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeAlreadyExists.selector, tradeId));
        registry.registerTrade(tradeId, 0, 3);
    }

    function test_registerTrade_revert_subTradeCountTooLow() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.InvalidSubTradeCount.selector, 1));
        registry.registerTrade(keccak256("trade-1"), 0, 1);
    }

    function test_registerTrade_revert_subTradeCountZero() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.InvalidSubTradeCount.selector, 0));
        registry.registerTrade(keccak256("trade-1"), 0, 0);
    }

    function test_registerTrade_revert_subTradeCountTooHigh() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.InvalidSubTradeCount.selector, 101));
        registry.registerTrade(keccak256("trade-1"), 0, 101);
    }

    function test_registerTrade_boundsAccepted() public {
        vm.startPrank(alice);
        registry.registerTrade(keccak256("trade-min"), 0, 2);
        registry.registerTrade(keccak256("trade-max"), 0, 100);
        vm.stopPrank();

        assertEq(registry.getSettlement(keccak256("trade-min")).subTradeCount, 2);
        assertEq(registry.getSettlement(keccak256("trade-max")).subTradeCount, 100);
    }

    // -------------------------------------------------------------------------
    // recordSubSettlement
    // -------------------------------------------------------------------------

    function test_recordSubSettlement_storesAndIncrements() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 3);

        bytes32 proofHash = _submitComplianceForAlice(0);

        vm.prank(alice);
        registry.recordSubSettlement(tradeId, 0, proofHash);

        ISettlementRegistry.Settlement memory s = registry.getSettlement(tradeId);
        assertEq(s.settledCount, 1);

        ISettlementRegistry.SubSettlement[] memory subs = registry.getSubSettlements(tradeId);
        assertEq(subs.length, 1);
        assertEq(subs[0].index, 0);
        assertEq(subs[0].proofHash, proofHash);
        assertEq(subs[0].settledAt, block.timestamp);
    }

    function test_recordSubSettlement_emitsEvent() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proofHash = _submitComplianceForAlice(0);

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit ISettlementRegistry.SubSettlementRecorded(tradeId, 0, proofHash);
        registry.recordSubSettlement(tradeId, 0, proofHash);
    }

    function test_recordSubSettlement_revert_notSubject() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proofHash = _submitComplianceForAlice(0);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.NotTradeSubject.selector, bob, alice));
        registry.recordSubSettlement(tradeId, 0, proofHash);
    }

    function test_recordSubSettlement_revert_indexOutOfBounds() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proofHash = _submitComplianceForAlice(0);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.SubTradeIndexOutOfBounds.selector, 2, 2));
        registry.recordSubSettlement(tradeId, 2, proofHash);
    }

    function test_recordSubSettlement_revert_alreadySettled() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proofHash1 = _submitComplianceForAlice(0);
        bytes32 proofHash2 = _submitComplianceForAlice(0);

        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proofHash1);

        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.SubTradeAlreadySettled.selector, tradeId, 0));
        registry.recordSubSettlement(tradeId, 0, proofHash2);
        vm.stopPrank();
    }

    function test_recordSubSettlement_revert_attestationNotFound() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 fakeProofHash = bytes32(uint256(0xdead));

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.AttestationNotFound.selector, fakeProofHash));
        registry.recordSubSettlement(tradeId, 0, fakeProofHash);
    }

    function test_recordSubSettlement_revert_subjectMismatch() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        // Bob submits a proof to the oracle (proof belongs to bob, not alice)
        bytes32 proofHash = _submitComplianceFor(bob, 0);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.SubjectMismatch.selector, alice, bob));
        registry.recordSubSettlement(tradeId, 0, proofHash);
    }

    function test_recordSubSettlement_revert_jurisdictionMismatch() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2); // jurisdiction 0 (EU)

        // Alice submits a proof for jurisdiction 2 (UK). UK is permissive (does not
        // require signed signals), preserving the test's focus on jurisdiction-mismatch
        // detection at the SettlementRegistry boundary.
        bytes32 proofHash = _submitComplianceForAlice(2);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.JurisdictionMismatch.selector, 0, 2));
        registry.recordSubSettlement(tradeId, 0, proofHash);
    }

    function test_recordSubSettlement_revert_tradeExpired() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proofHash = _submitComplianceForAlice(0);

        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeExpiredError.selector, tradeId));
        registry.recordSubSettlement(tradeId, 0, proofHash);
    }

    function test_recordSubSettlement_revert_tradeNotFound() public {
        bytes32 tradeId = keccak256("nonexistent");
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeNotFound.selector, tradeId));
        registry.recordSubSettlement(tradeId, 0, bytes32(uint256(1)));
    }

    function test_recordSubSettlement_revert_tradeAlreadyFinalized() public {
        bytes32 tradeId = _setupAndFinalizeTradeForAlice();

        bytes32 proofHash = _submitComplianceForAlice(0);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeAlreadyFinalized.selector, tradeId));
        registry.recordSubSettlement(tradeId, 0, proofHash);
    }

    // -------------------------------------------------------------------------
    // finalizeTrade
    // -------------------------------------------------------------------------

    function test_finalizeTrade_succeeds() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        // Record two sub-settlements
        bytes32 proof1 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);
        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);
        registry.recordSubSettlement(tradeId, 1, proof2);
        vm.stopPrank();

        // Submit pattern proof
        (bytes32 patternProof, bytes memory patternInputs) = _submitPatternForAlice();

        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit ISettlementRegistry.TradeFinalized(tradeId, block.timestamp);
        registry.finalizeTrade(tradeId, patternProof, patternInputs);

        ISettlementRegistry.Settlement memory s = registry.getSettlement(tradeId);
        assertTrue(s.finalized);
    }

    function test_finalizeTrade_revert_notComplete() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        // Only record one sub-settlement
        bytes32 proof1 = _submitComplianceForAlice(0);
        vm.prank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);

        (bytes32 patternProof, bytes memory patternInputs) = _submitPatternForAlice();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeNotComplete.selector, tradeId, 1, 2));
        registry.finalizeTrade(tradeId, patternProof, patternInputs);
    }

    function test_finalizeTrade_revert_alreadyFinalized() public {
        bytes32 tradeId = _setupAndFinalizeTradeForAlice();

        (bytes32 patternProof, bytes memory patternInputs) = _submitPatternForAlice();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeAlreadyFinalized.selector, tradeId));
        registry.finalizeTrade(tradeId, patternProof, patternInputs);
    }

    function test_finalizeTrade_revert_patternProofZero() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proof1 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);
        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);
        registry.recordSubSettlement(tradeId, 1, proof2);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.PatternProofRequired.selector, tradeId));
        registry.finalizeTrade(tradeId, bytes32(0), "");
    }

    function test_finalizeTrade_revert_patternProofNotFound() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proof1 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);
        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);
        registry.recordSubSettlement(tradeId, 1, proof2);
        vm.stopPrank();

        bytes32 fakeProof = bytes32(uint256(0xdead));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.AttestationNotFound.selector, fakeProof));
        registry.finalizeTrade(tradeId, fakeProof, "");
    }

    function test_finalizeTrade_revert_patternProofSubjectMismatch() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proof1 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);
        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);
        registry.recordSubSettlement(tradeId, 1, proof2);
        vm.stopPrank();

        // Bob submits pattern proof (wrong subject)
        (bytes32 patternProof, bytes memory patternInputs) = _submitPatternFor(bob, 1);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.SubjectMismatch.selector, alice, bob));
        registry.finalizeTrade(tradeId, patternProof, patternInputs);
    }

    function test_finalizeTrade_revert_patternProofTooOld() public {
        // Submit pattern proof BEFORE registering the trade
        (bytes32 patternProof, bytes memory patternInputs) = _submitPatternForAlice();

        vm.warp(block.timestamp + 1); // advance time so createdAt > pattern timestamp

        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proof1 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);
        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);
        registry.recordSubSettlement(tradeId, 1, proof2);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.PatternProofRequired.selector, tradeId));
        registry.finalizeTrade(tradeId, patternProof, patternInputs);
    }

    function test_finalizeTrade_revert_wrongProofType() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proof1 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);
        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);
        registry.recordSubSettlement(tradeId, 1, proof2);
        vm.stopPrank();

        // Try to use a COMPLIANCE proof (not PATTERN) as the pattern proof
        bytes32 complianceProof = _submitComplianceForAlice(0);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.PatternProofRequired.selector, tradeId));
        registry.finalizeTrade(tradeId, complianceProof, "");
    }

    function test_finalizeTrade_revert_notSubject() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proof1 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);
        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);
        registry.recordSubSettlement(tradeId, 1, proof2);
        vm.stopPrank();

        (bytes32 patternProof, bytes memory patternInputs) = _submitPatternForAlice();

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.NotTradeSubject.selector, bob, alice));
        registry.finalizeTrade(tradeId, patternProof, patternInputs);
    }

    function test_finalizeTrade_revert_tradeExpired() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proof1 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);
        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);
        registry.recordSubSettlement(tradeId, 1, proof2);
        vm.stopPrank();

        vm.warp(block.timestamp + 7 days + 1);

        (bytes32 patternProof, bytes memory patternInputs) = _submitPatternForAlice();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeExpiredError.selector, tradeId));
        registry.finalizeTrade(tradeId, patternProof, patternInputs);
    }

    // -------------------------------------------------------------------------
    // H-2: PATTERN analysis_type binding
    // -------------------------------------------------------------------------

    function test_finalizeTrade_revert_velocityAnalysisRejected() public {
        bytes32 tradeId = keccak256("trade-velocity");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proof1 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);
        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);
        registry.recordSubSettlement(tradeId, 1, proof2);
        vm.stopPrank();

        // Submit a VELOCITY (analysis_type=2) pattern proof, not STRUCTURING.
        (bytes32 patternProof, bytes memory patternInputs) = _submitPatternFor(alice, 2);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.PatternAnalysisTypeMismatch.selector, 1, 2));
        registry.finalizeTrade(tradeId, patternProof, patternInputs);
    }

    function test_finalizeTrade_revert_roundAmountAnalysisRejected() public {
        bytes32 tradeId = keccak256("trade-round");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proof1 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);
        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);
        registry.recordSubSettlement(tradeId, 1, proof2);
        vm.stopPrank();

        (bytes32 patternProof, bytes memory patternInputs) = _submitPatternFor(alice, 3);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.PatternAnalysisTypeMismatch.selector, 1, 3));
        registry.finalizeTrade(tradeId, patternProof, patternInputs);
    }

    function test_finalizeTrade_revert_publicInputsMismatch() public {
        bytes32 tradeId = keccak256("trade-mismatch");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proof1 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);
        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);
        registry.recordSubSettlement(tradeId, 1, proof2);
        vm.stopPrank();

        (bytes32 patternProof,) = _submitPatternForAlice();

        // Tampered inputs: substitute analysis_type 1 for 1 but change tx_set_hash
        bytes memory tamperedInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(1)), // result
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0xbeef)), // tx_set_hash (different from original 0xabcd)
            bytes32(uint256(uint160(alice)))
        );

        vm.prank(alice);
        vm.expectRevert(); // PatternPublicInputsMismatch with hash data
        registry.finalizeTrade(tradeId, patternProof, tamperedInputs);
    }

    function test_submitCompliance_revert_pattern_invalidAnalysisType() public {
        // Oracle should reject analysis_type==99
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(99)), // analysis_type (invalid)
            bytes32(uint256(1)), // result
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0xabcd)), // tx_set_hash
            bytes32(uint256(uint160(alice)))
        );
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidAnalysisType.selector, 99));
        oracle.submitCompliance(0, ProofTypes.PATTERN, proof, publicInputs, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // expireTrade
    // -------------------------------------------------------------------------

    function test_expireTrade_afterExpiry() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        vm.warp(block.timestamp + 7 days + 1);

        vm.expectEmit(true, false, false, true);
        emit ISettlementRegistry.TradeExpired(tradeId, block.timestamp);
        registry.expireTrade(tradeId);

        ISettlementRegistry.Settlement memory s = registry.getSettlement(tradeId);
        assertTrue(s.finalized);
    }

    function test_expireTrade_permissionless() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        vm.warp(block.timestamp + 7 days + 1);

        // Bob (not the subject) can expire it
        vm.prank(bob);
        registry.expireTrade(tradeId);

        assertTrue(registry.getSettlement(tradeId).finalized);
    }

    function test_expireTrade_revert_beforeExpiry() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeNotExpired.selector, tradeId));
        registry.expireTrade(tradeId);
    }

    function test_expireTrade_revert_atExactExpiry() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        vm.warp(block.timestamp + 7 days); // exactly at expiry, not past

        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeNotExpired.selector, tradeId));
        registry.expireTrade(tradeId);
    }

    function test_expireTrade_revert_alreadyFinalized() public {
        bytes32 tradeId = _setupAndFinalizeTradeForAlice();

        vm.warp(block.timestamp + 7 days + 1);

        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeAlreadyFinalized.selector, tradeId));
        registry.expireTrade(tradeId);
    }

    function test_expireTrade_revert_tradeNotFound() public {
        bytes32 tradeId = keccak256("nonexistent");
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeNotFound.selector, tradeId));
        registry.expireTrade(tradeId);
    }

    // -------------------------------------------------------------------------
    // getSettlement
    // -------------------------------------------------------------------------

    function test_getSettlement_returnsCorrectData() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 1, 5);

        ISettlementRegistry.Settlement memory s = registry.getSettlement(tradeId);
        assertEq(s.tradeId, tradeId);
        assertEq(s.subject, alice);
        assertEq(s.jurisdictionId, 1);
        assertEq(s.subTradeCount, 5);
        assertEq(s.settledCount, 0);
    }

    function test_getSettlement_revert_notFound() public {
        bytes32 tradeId = keccak256("nonexistent");
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeNotFound.selector, tradeId));
        registry.getSettlement(tradeId);
    }

    // -------------------------------------------------------------------------
    // getSubSettlements
    // -------------------------------------------------------------------------

    function test_getSubSettlements_returnsAllRecorded() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 3);

        bytes32 proof0 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);

        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof0);
        registry.recordSubSettlement(tradeId, 2, proof2);
        vm.stopPrank();

        ISettlementRegistry.SubSettlement[] memory subs = registry.getSubSettlements(tradeId);
        assertEq(subs.length, 2);
        assertEq(subs[0].index, 0);
        assertEq(subs[0].proofHash, proof0);
        assertEq(subs[1].index, 2);
        assertEq(subs[1].proofHash, proof2);
    }

    function test_getSubSettlements_emptyWhenNoneRecorded() public {
        bytes32 tradeId = keccak256("trade-1");
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        ISettlementRegistry.SubSettlement[] memory subs = registry.getSubSettlements(tradeId);
        assertEq(subs.length, 0);
    }

    function test_getSubSettlements_revert_notFound() public {
        bytes32 tradeId = keccak256("nonexistent");
        vm.expectRevert(abi.encodeWithSelector(ISettlementRegistry.TradeNotFound.selector, tradeId));
        registry.getSubSettlements(tradeId);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    uint256 internal _proofNonce;

    function _uniqueProof() internal returns (bytes memory) {
        _proofNonce++;
        bytes memory proof = new bytes(2144);
        bytes32 nonceBytes = bytes32(_proofNonce);
        for (uint256 i; i < 32; i++) {
            proof[i] = nonceBytes[i];
        }
        return proof;
    }

    /// @dev Submit a compliance proof to the oracle as alice, return the proofHash
    function _submitComplianceForAlice(uint8 jurisdictionId) internal returns (bytes32 proofHash) {
        return _submitComplianceFor(alice, jurisdictionId);
    }

    /// @dev Submit a compliance proof to the oracle as `who`, return the proofHash
    function _submitComplianceFor(address who, uint8 jurisdictionId) internal returns (bytes32 proofHash) {
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(jurisdictionId)),
            DEFAULT_PROVIDER_SET_HASH,
            INITIAL_CONFIG,
            bytes32(block.timestamp),
            bytes32(uint256(1)),
            bytes32(uint256(uint160(who)))
        );
        vm.prank(who);
        oracle.submitCompliance(jurisdictionId, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);
        proofHash = oracle.computeProofHash(proof, ProofTypes.COMPLIANCE);
    }

    /// @dev Submit a STRUCTURING pattern proof to the oracle as alice, return hash + inputs
    function _submitPatternForAlice() internal returns (bytes32 proofHash, bytes memory publicInputs) {
        return _submitPatternFor(alice, 1);
    }

    /// @dev Back-compat helper for tests that only need the hash
    function _submitPatternForAliceHash() internal returns (bytes32 proofHash) {
        (proofHash,) = _submitPatternFor(alice, 1);
    }

    /// @dev Submit a pattern proof to the oracle as `who`, return the proofHash + inputs.
    ///      `analysisType` controls the pattern analysis (1=structuring, 2=velocity, 3=round-amounts).
    function _submitPatternFor(address who, uint256 analysisType)
        internal
        returns (bytes32 proofHash, bytes memory publicInputs)
    {
        bytes memory proof = _uniqueProof();
        publicInputs = abi.encodePacked(
            bytes32(analysisType), // analysis_type
            bytes32(uint256(1)), // result
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0xabcd)), // tx_set_hash
            bytes32(uint256(uint160(who))) // submitter
        );
        vm.prank(who);
        oracle.submitCompliance(0, ProofTypes.PATTERN, proof, publicInputs, bytes32(0));
        proofHash = oracle.computeProofHash(proof, ProofTypes.PATTERN);
    }

    /// @dev Full helper: register trade with 2 sub-trades, settle both, finalize
    function _setupAndFinalizeTradeForAlice() internal returns (bytes32 tradeId) {
        tradeId = keccak256(abi.encodePacked("finalized-trade-", _proofNonce));
        vm.prank(alice);
        registry.registerTrade(tradeId, 0, 2);

        bytes32 proof1 = _submitComplianceForAlice(0);
        bytes32 proof2 = _submitComplianceForAlice(0);
        vm.startPrank(alice);
        registry.recordSubSettlement(tradeId, 0, proof1);
        registry.recordSubSettlement(tradeId, 1, proof2);
        vm.stopPrank();

        (bytes32 patternProof, bytes memory patternInputs) = _submitPatternForAlice();

        vm.prank(alice);
        registry.finalizeTrade(tradeId, patternProof, patternInputs);
    }
}
