// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {JurisdictionConfig} from "../src/libraries/JurisdictionConfig.sol";

/// @notice Cross-validates the Solidity `JurisdictionConfig.getHighRiskThreshold`
///         values against the Noir `circuits/shared/src/risk.nr::get_high_threshold`
///         values. The Solidity side uses percentage scale (0-100); the Noir side
///         uses basis points (0-10000). The relationship Solidity * 100 == Noir
///         must hold at all times -- a drift breaks every legitimate compliance
///         proof for the affected jurisdiction (the in-circuit threshold check
///         would yield a different `meets_threshold` than the on-chain validator
///         expects).
///
///         The expected basis-point values below mirror `get_high_threshold` in
///         `circuits/shared/src/risk.nr` line-for-line. If you change one side,
///         update both AND regenerate fixtures (`make fixtures`).
contract JurisdictionThresholdParityTest is Test {
    /// @dev Mirror of `circuits/shared/src/risk.nr::get_high_threshold` return values.
    function _expectedBps(uint8 jurisdictionId) internal pure returns (uint32) {
        if (jurisdictionId == JurisdictionConfig.EU) return 7100; // 71%
        if (jurisdictionId == JurisdictionConfig.US) return 6600; // 66%
        if (jurisdictionId == JurisdictionConfig.UK) return 7100; // 71%
        if (jurisdictionId == JurisdictionConfig.SINGAPORE) return 7600; // 76%
        revert("unknown jurisdiction in test mirror");
    }

    function test_parity_eu() public pure {
        _assertParity(JurisdictionConfig.EU);
    }

    function test_parity_us() public pure {
        _assertParity(JurisdictionConfig.US);
    }

    function test_parity_uk() public pure {
        _assertParity(JurisdictionConfig.UK);
    }

    function test_parity_singapore() public pure {
        _assertParity(JurisdictionConfig.SINGAPORE);
    }

    /// @notice Iterates every defined jurisdiction. Adding a new one without
    ///         updating `_expectedBps` will revert here, forcing the parity
    ///         table to stay in sync.
    function test_parity_allJurisdictions() public pure {
        for (uint8 j = JurisdictionConfig.EU; j <= JurisdictionConfig.SINGAPORE; j++) {
            _assertParity(j);
        }
    }

    function _assertParity(uint8 jurisdictionId) internal pure {
        uint8 solPercent = JurisdictionConfig.getHighRiskThreshold(jurisdictionId);
        uint32 expectedBps = _expectedBps(jurisdictionId);
        assertEq(
            uint256(solPercent) * 100,
            uint256(expectedBps),
            "Solidity highFloor * 100 must equal Noir get_high_threshold (basis points)"
        );
    }
}
