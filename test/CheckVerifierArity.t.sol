// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {CheckVerifierArity} from "../script/CheckVerifierArity.s.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";
import {PassingVerifier} from "./utils/TestStubs.sol";

/// @dev The pre-proposal check refuses a generated verifier whose public-input count differs
///      from `ProofTypes.expectedPublicInputCount` (README "A public-input layout change
///      requires a full redeploy").
contract CheckVerifierArityTest is Test {
    CheckVerifierArity internal checker;
    address internal riskScoreVerifier;
    address internal patternVerifier;

    function setUp() public {
        checker = new CheckVerifierArity();
        riskScoreVerifier = deployCode("risk_score_verifier.sol:RiskScoreVerifier");
        patternVerifier = deployCode("pattern_verifier.sol:PatternVerifier");
    }

    function test_check_acceptsMatchingArity() public view {
        assertEq(checker.check(riskScoreVerifier, ProofTypes.RISK_SCORE), 9);
        assertEq(checker.check(patternVerifier, ProofTypes.PATTERN), 8);
    }

    function test_check_refusesWrongArity() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CheckVerifierArity.ArityMismatch.selector, patternVerifier, ProofTypes.RISK_SCORE, uint256(9)
            )
        );
        checker.check(patternVerifier, ProofTypes.RISK_SCORE);
    }

    /// @dev A candidate that does not report its proof length the bb way is refused, not passed.
    function test_check_refusesUnrecognisedVerifier() public {
        address stub = address(new PassingVerifier());
        vm.expectRevert(abi.encodeWithSelector(CheckVerifierArity.CannotReadProofLength.selector, stub));
        checker.check(stub, ProofTypes.RISK_SCORE);
    }
}
