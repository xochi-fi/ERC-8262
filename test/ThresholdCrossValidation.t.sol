// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {JurisdictionConfig} from "../src/libraries/JurisdictionConfig.sol";

/// @notice Cross-validation: Solidity thresholds must match Noir circuit constants.
///         Noir uses basis points (0-10000), Solidity uses percentage (0-100).
///         Conversion: solidity_value * 100 = noir_value.
///         If this test fails, check circuits/shared/src/risk.nr get_high_threshold().
contract ThresholdCrossValidationTest is Test {
    // Expected Noir threshold values (basis points) from circuits/shared/src/risk.nr
    uint256 constant NOIR_EU_THRESHOLD = 7100;
    uint256 constant NOIR_US_THRESHOLD = 6600;
    uint256 constant NOIR_UK_THRESHOLD = 7100;
    uint256 constant NOIR_SG_THRESHOLD = 7600;

    function test_eu_threshold_matches_noir() public pure {
        assertEq(uint256(JurisdictionConfig.getHighRiskThreshold(0)) * 100, NOIR_EU_THRESHOLD);
    }

    function test_us_threshold_matches_noir() public pure {
        assertEq(uint256(JurisdictionConfig.getHighRiskThreshold(1)) * 100, NOIR_US_THRESHOLD);
    }

    function test_uk_threshold_matches_noir() public pure {
        assertEq(uint256(JurisdictionConfig.getHighRiskThreshold(2)) * 100, NOIR_UK_THRESHOLD);
    }

    function test_sg_threshold_matches_noir() public pure {
        assertEq(uint256(JurisdictionConfig.getHighRiskThreshold(3)) * 100, NOIR_SG_THRESHOLD);
    }

    function test_all_jurisdictions_exhaustive() public pure {
        uint256[4] memory expected = [NOIR_EU_THRESHOLD, NOIR_US_THRESHOLD, NOIR_UK_THRESHOLD, NOIR_SG_THRESHOLD];
        for (uint8 j; j < 4; j++) {
            assertEq(
                uint256(JurisdictionConfig.getHighRiskThreshold(j)) * 100,
                expected[j],
                "Threshold mismatch -- update circuits/shared/src/risk.nr"
            );
        }
    }
}
