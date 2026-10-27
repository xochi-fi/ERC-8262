// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {CheckVerifierArity} from "../script/CheckVerifierArity.s.sol";
import {ERC8262Verifier} from "../src/ERC8262Verifier.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";
import {PassingVerifier} from "./utils/TestStubs.sol";

/// @dev Answers the empty-proof probe the bb way, then accepts any correctly sized proof
///      with `inputs` public inputs: a soundness failure the check must refuse.
contract AcceptAllBbShapedVerifier {
    error ProofLengthWrongWithLogN(uint256 logN, uint256 actualLength, uint256 expectedLength);
    error PublicInputsLengthWrong();

    uint256 internal immutable inputs;

    constructor(uint256 inputs_) {
        inputs = inputs_;
    }

    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        if (proof.length != 8640) revert ProofLengthWrongWithLogN(20, proof.length, 8640);
        if (publicInputs.length != inputs) revert PublicInputsLengthWrong();
        return true;
    }
}

/// @dev Answers the empty-proof probe the bb way, then reverts with an unrelated error for
///      every input count, so its arity cannot be confirmed.
contract LengthReporterThenOtherError {
    error ProofLengthWrongWithLogN(uint256 logN, uint256 actualLength, uint256 expectedLength);
    error Unrelated();

    function verify(bytes calldata proof, bytes32[] calldata) external pure returns (bool) {
        if (proof.length != 8640) revert ProofLengthWrongWithLogN(20, proof.length, 8640);
        revert Unrelated();
    }
}

/// @dev The pre-proposal check refuses a generated verifier whose public-input count differs
///      from `ProofTypes.expectedPublicInputCount` or from the router's live verifier (README
///      "A public-input layout change requires a full redeploy").
contract CheckVerifierArityTest is Test {
    CheckVerifierArity internal checker;
    ERC8262Verifier internal router;
    address internal riskScoreVerifier;
    address internal patternVerifier;

    function setUp() public {
        checker = new CheckVerifierArity();
        router = new ERC8262Verifier(address(this));
        riskScoreVerifier = deployCode("risk_score_verifier.sol:RiskScoreVerifier");
        patternVerifier = deployCode("pattern_verifier.sol:PatternVerifier");
    }

    function test_check_acceptsMatchingArity() public view {
        assertEq(checker.check(address(0), riskScoreVerifier, ProofTypes.RISK_SCORE), 9);
        assertEq(checker.check(address(0), patternVerifier, ProofTypes.PATTERN), 8);
    }

    function test_check_acceptsMatchingLiveVerifier() public {
        router.setVerifierInitial(ProofTypes.RISK_SCORE, riskScoreVerifier);
        address candidate = deployCode("risk_score_verifier.sol:RiskScoreVerifier");
        assertEq(checker.check(address(router), candidate, ProofTypes.RISK_SCORE), 9);
    }

    /// @dev No live verifier for the type yet (initial setup): only the checkout's count applies.
    function test_check_acceptsWhenNoLiveVerifier() public view {
        assertEq(checker.check(address(router), riskScoreVerifier, ProofTypes.RISK_SCORE), 9);
    }

    function test_check_refusesWrongArity() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CheckVerifierArity.ArityMismatch.selector, patternVerifier, ProofTypes.RISK_SCORE, uint256(9)
            )
        );
        checker.check(address(0), patternVerifier, ProofTypes.RISK_SCORE);
    }

    /// @dev The router routes RISK_SCORE to an 8-input verifier, as a deployment built from
    ///      another commit would: the checkout's 9 is not trusted.
    function test_check_refusesLiveArityMismatch() public {
        router.setVerifierInitial(ProofTypes.RISK_SCORE, patternVerifier);
        vm.expectRevert(
            abi.encodeWithSelector(
                CheckVerifierArity.LiveArityMismatch.selector, patternVerifier, ProofTypes.RISK_SCORE, uint256(9)
            )
        );
        checker.check(address(router), riskScoreVerifier, ProofTypes.RISK_SCORE);
    }

    /// @dev A candidate that does not report its proof length the bb way is refused, not passed.
    function test_check_refusesUnrecognisedVerifier() public {
        address stub = address(new PassingVerifier());
        vm.expectRevert(abi.encodeWithSelector(CheckVerifierArity.CannotReadProofLength.selector, stub));
        checker.check(address(0), stub, ProofTypes.RISK_SCORE);
    }

    function test_check_refusesVerifierAcceptingZeroProof() public {
        address stub = address(new AcceptAllBbShapedVerifier(9));
        vm.expectRevert(abi.encodeWithSelector(CheckVerifierArity.AcceptsZeroProof.selector, stub));
        checker.check(address(0), stub, ProofTypes.RISK_SCORE);
    }

    function test_check_refusesUnconfirmedArity() public {
        address stub = address(new LengthReporterThenOtherError());
        vm.expectRevert(abi.encodeWithSelector(CheckVerifierArity.CannotConfirmArity.selector, stub));
        checker.check(address(0), stub, ProofTypes.RISK_SCORE);
    }

    function test_check_refusesInvalidProofType() public {
        vm.expectRevert(abi.encodeWithSelector(CheckVerifierArity.ProofTypeOutOfRange.selector, uint256(0)));
        checker.check(address(0), riskScoreVerifier, 0);
    }

    /// @dev `PROOF_TYPE=258` must not truncate to 0x02.
    function test_run_refusesProofTypeAboveUint8() public {
        vm.setEnv("VERIFIER_CANDIDATE", vm.toString(riskScoreVerifier));
        vm.setEnv("PROOF_TYPE", "258");
        vm.expectRevert(abi.encodeWithSelector(CheckVerifierArity.ProofTypeOutOfRange.selector, uint256(258)));
        checker.run();
    }
}
