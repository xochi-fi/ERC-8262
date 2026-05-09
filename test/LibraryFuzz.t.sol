// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";
import {JurisdictionConfig} from "../src/libraries/JurisdictionConfig.sol";

contract ProofTypesHarness {
    function decodePublicInputs(bytes calldata packed) external pure returns (bytes32[] memory) {
        return ProofTypes.decodePublicInputs(packed);
    }

    function validatePublicInputs(uint8 proofType, bytes calldata publicInputs) external pure {
        ProofTypes.validatePublicInputs(proofType, publicInputs);
    }

    function expectedPublicInputCount(uint8 proofType) external pure returns (uint256) {
        return ProofTypes.expectedPublicInputCount(proofType);
    }
}

contract JurisdictionHarness {
    function meetsThreshold(uint8 score, uint8 jurisdictionId) external pure returns (bool) {
        return JurisdictionConfig.meetsThreshold(score, jurisdictionId);
    }

    function getRiskTier(uint8 score, uint8 jurisdictionId) external pure returns (uint8) {
        return JurisdictionConfig.getRiskTier(score, jurisdictionId);
    }
}

contract LibraryFuzzTest is Test {
    ProofTypesHarness internal proofTypes;
    JurisdictionHarness internal jurisdiction;

    function setUp() public {
        proofTypes = new ProofTypesHarness();
        jurisdiction = new JurisdictionHarness();
    }

    // -------------------------------------------------------------------------
    // ProofTypes.decodePublicInputs fuzz
    // -------------------------------------------------------------------------

    function testFuzz_decodePublicInputs_roundTrip(bytes32[5] memory slots) public view {
        bytes memory packed = abi.encodePacked(slots[0], slots[1], slots[2], slots[3], slots[4]);
        bytes32[] memory decoded = proofTypes.decodePublicInputs(packed);
        assertEq(decoded.length, 5);
        for (uint256 i; i < 5; i++) {
            assertEq(decoded[i], slots[i]);
        }
    }

    function testFuzz_decodePublicInputs_arbitraryLength(uint8 count) public view {
        count = uint8(bound(count, 1, 32));
        bytes memory packed = new bytes(uint256(count) * 32);
        for (uint256 i; i < count; i++) {
            bytes32 val = keccak256(abi.encodePacked(i));
            assembly {
                mstore(add(packed, add(32, mul(i, 32))), val)
            }
        }
        bytes32[] memory decoded = proofTypes.decodePublicInputs(packed);
        assertEq(decoded.length, count);
        for (uint256 i; i < count; i++) {
            assertEq(decoded[i], keccak256(abi.encodePacked(i)));
        }
    }

    function testFuzz_validatePublicInputs_revert_wrongCount(uint8 proofType, uint8 extraSlots) public {
        proofType = uint8(bound(proofType, 1, 8));
        extraSlots = uint8(bound(extraSlots, 1, 10));
        uint256 expected = proofTypes.expectedPublicInputCount(proofType);
        uint256 wrongCount = expected + extraSlots;
        bytes memory packed = new bytes(wrongCount * 32);
        vm.expectRevert(
            abi.encodeWithSelector(ProofTypes.InvalidPublicInputLength.selector, proofType, expected, wrongCount)
        );
        proofTypes.validatePublicInputs(proofType, packed);
    }

    function testFuzz_validatePublicInputs_revert_unaligned(uint8 proofType, uint8 extraBytes) public {
        proofType = uint8(bound(proofType, 1, 8));
        extraBytes = uint8(bound(extraBytes, 1, 31));
        uint256 expected = proofTypes.expectedPublicInputCount(proofType);
        bytes memory packed = new bytes(expected * 32 + extraBytes);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.UnalignedPublicInputs.selector, packed.length));
        proofTypes.validatePublicInputs(proofType, packed);
    }

    function test_expectedPublicInputCount_signedVariants() public view {
        // Signed variants add signer_pubkey_hash + chain_id + oracle_address (audit F-6)
        // to their unsigned siblings -- 3 extra slots each.
        assertEq(proofTypes.expectedPublicInputCount(ProofTypes.COMPLIANCE_SIGNED), 9);
        assertEq(proofTypes.expectedPublicInputCount(ProofTypes.RISK_SCORE_SIGNED), 11);
    }

    // -------------------------------------------------------------------------
    // JurisdictionConfig.meetsThreshold fuzz
    // -------------------------------------------------------------------------

    function testFuzz_meetsThreshold_allJurisdictions(uint8 score, uint8 jurisdictionId) public view {
        jurisdictionId = uint8(bound(jurisdictionId, 0, 3));
        score = uint8(bound(score, 0, 100));

        bool result = jurisdiction.meetsThreshold(score, jurisdictionId);
        uint8 tier = jurisdiction.getRiskTier(score, jurisdictionId);

        // meetsThreshold <=> score < highFloor <=> tier != TIER_HIGH
        if (tier == 2) {
            assertFalse(result);
        } else {
            assertTrue(result);
        }
    }

    function testFuzz_meetsThreshold_boundary(uint8 jurisdictionId) public view {
        jurisdictionId = uint8(bound(jurisdictionId, 0, 3));

        JurisdictionConfig.Thresholds memory t = JurisdictionConfig.getThresholds(jurisdictionId);

        assertTrue(jurisdiction.meetsThreshold(t.highFloor - 1, jurisdictionId));
        assertFalse(jurisdiction.meetsThreshold(t.highFloor, jurisdictionId));
    }

    function testFuzz_meetsThreshold_revert_invalidJurisdiction(uint8 jurisdictionId) public {
        vm.assume(jurisdictionId > 3);
        vm.expectRevert(abi.encodeWithSelector(JurisdictionConfig.InvalidJurisdiction.selector, jurisdictionId));
        jurisdiction.meetsThreshold(50, jurisdictionId);
    }

    function testFuzz_getRiskTier_consistency(uint8 score, uint8 jurisdictionId) public view {
        jurisdictionId = uint8(bound(jurisdictionId, 0, 3));
        score = uint8(bound(score, 0, 100));

        uint8 tier = jurisdiction.getRiskTier(score, jurisdictionId);
        assertTrue(tier <= 2);

        JurisdictionConfig.Thresholds memory t = JurisdictionConfig.getThresholds(jurisdictionId);

        if (score >= t.highFloor) {
            assertEq(tier, 2);
        } else if (score >= t.mediumFloor) {
            assertEq(tier, 1);
        } else {
            assertEq(tier, 0);
        }
    }
}
