// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {IERC8262Verifier} from "../src/interfaces/IERC8262Verifier.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";

/// @title CheckVerifierArity -- refuse a candidate verifier whose public-input count differs
///        from the deployed system's
/// @notice `ERC8262Verifier.setVerifierInitial` / `proposeVerifier` check code presence, codehash
///         and revocation, not the public-input count. `ProofTypes.expectedPublicInputCount` is
///         inlined into the Oracle and the router at deploy time, so a verifier for a circuit with
///         a different count passes the proposal and, once executed, makes every submission of
///         that type revert `PublicInputsLengthWrong()`; recovery costs another timelock delay.
///         Run this read-only check against the candidate before proposing it.
///
///         The expected count is this checkout's `ProofTypes`. Given the deployed router, the
///         verifier it currently routes `proofType` to must accept the same count, so a checkout
///         that is not the deployed commit is refused rather than trusted. When that live verifier
///         is itself the broken one (the recovery case), the check refuses too: confirm the
///         checkout is the deployed commit and run without `VERIFIER_ROUTER`.
///
///         The probe relies on the bb-generated `BaseZKHonkVerifier`, which checks the proof
///         length, then the public-input count, before any cryptography: an empty proof makes it
///         report the proof length it expects, and an all-zero proof of that length reaches the
///         count check. A verifier passes only if it answers the empty proof that way, answers
///         the all-zero proof with exactly `PublicInputsLengthWrong()` at one more input than
///         expected, does not answer it that way at the expected count, and does not accept the
///         all-zero proof. Every other answer is refused.
///
/// Usage:
///   VERIFIER_CANDIDATE=0x... PROOF_TYPE=2 VERIFIER_ROUTER=0x... \
///     forge script script/CheckVerifierArity.s.sol --rpc-url $RPC_URL
contract CheckVerifierArity is Script {
    error ProofTypeOutOfRange(uint256 proofType);
    error CannotReadProofLength(address verifier);
    error AcceptsZeroProof(address verifier);
    error CannotConfirmArity(address verifier);
    error ArityMismatch(address candidate, uint8 proofType, uint256 expectedInputs);
    error LiveArityMismatch(address liveVerifier, uint8 proofType, uint256 expectedInputs);

    bytes4 internal constant PROOF_LENGTH_WRONG_WITH_LOG_N =
        bytes4(keccak256("ProofLengthWrongWithLogN(uint256,uint256,uint256)"));
    bytes4 internal constant PUBLIC_INPUTS_LENGTH_WRONG = bytes4(keccak256("PublicInputsLengthWrong()"));

    function run() external view {
        address candidate = vm.envAddress("VERIFIER_CANDIDATE");
        uint256 rawProofType = vm.envUint("PROOF_TYPE");
        address router = vm.envOr("VERIFIER_ROUTER", address(0));
        if (rawProofType > type(uint8).max || !ProofTypes.isValidProofType(uint8(rawProofType))) {
            revert ProofTypeOutOfRange(rawProofType);
        }
        if (router == address(0)) console.log("VERIFIER_ROUTER unset: the live verifier is not compared");
        uint256 expectedInputs = check(router, candidate, uint8(rawProofType));
        console.log("Candidate accepts the expected public-input count:", expectedInputs);
    }

    /// @notice Reverts unless `candidate` accepts exactly `expectedPublicInputCount(proofType)`
    ///         inputs and, when `router` routes `proofType` to a verifier, that one does too.
    /// @param router Deployed `ERC8262Verifier`, or `address(0)` to skip the live comparison.
    function check(address router, address candidate, uint8 proofType) public view returns (uint256 expectedInputs) {
        if (!ProofTypes.isValidProofType(proofType)) revert ProofTypeOutOfRange(proofType);
        expectedInputs = ProofTypes.expectedPublicInputCount(proofType);
        if (!_acceptsExactly(candidate, expectedInputs)) revert ArityMismatch(candidate, proofType, expectedInputs);

        if (router == address(0)) return expectedInputs;
        address live = IERC8262Verifier(router).getVerifier(proofType);
        if (live != address(0) && !_acceptsExactly(live, expectedInputs)) {
            revert LiveArityMismatch(live, proofType, expectedInputs);
        }
    }

    /// @dev Whether `verifier` takes `count` public inputs: it passes the count check at
    ///      `count` and fails it, with exactly `PublicInputsLengthWrong()`, at `count + 1`.
    function _acceptsExactly(address verifier, uint256 count) internal view returns (bool) {
        uint256 proofLength = _proofLength(verifier);
        if (_failsCountCheck(verifier, proofLength, count)) return false;
        if (!_failsCountCheck(verifier, proofLength, count + 1)) revert CannotConfirmArity(verifier);
        return true;
    }

    /// @dev The proof length `verifier` expects, from its answer to an empty proof.
    function _proofLength(address verifier) internal view returns (uint256 proofLength) {
        (bool ok, bytes memory ret) = verifier.staticcall(abi.encodeCall(IUltraVerifier.verify, ("", new bytes32[](0))));
        // ProofLengthWrongWithLogN(logN, actualLength, expectedLength): selector + 3 words.
        if (ok || ret.length != 100 || bytes4(ret) != PROOF_LENGTH_WRONG_WITH_LOG_N) {
            revert CannotReadProofLength(verifier);
        }
        assembly {
            proofLength := mload(add(ret, 100))
        }
    }

    /// @dev Probes an all-zero proof with `count` zero inputs. True only for exactly
    ///      `PublicInputsLengthWrong()`; reverts if the verifier accepts the proof.
    function _failsCountCheck(address verifier, uint256 proofLength, uint256 count) internal view returns (bool) {
        (bool ok, bytes memory ret) =
            verifier.staticcall(abi.encodeCall(IUltraVerifier.verify, (new bytes(proofLength), new bytes32[](count))));
        if (ok && ret.length == 32 && abi.decode(ret, (bool))) revert AcceptsZeroProof(verifier);
        return !ok && ret.length == 4 && bytes4(ret) == PUBLIC_INPUTS_LENGTH_WRONG;
    }
}
