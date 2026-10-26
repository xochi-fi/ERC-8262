// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";

/// @title CheckVerifierArity -- refuse a candidate verifier whose public-input count differs
///        from the deployed Oracle's
/// @notice `ERC8262Verifier.setVerifierInitial` / `proposeVerifier` check code presence, codehash
///         and revocation, not the public-input count. `ProofTypes.expectedPublicInputCount` is
///         inlined into the Oracle and the router at deploy time, so a verifier for a circuit with
///         a different count passes the proposal and, once executed, makes every submission of
///         that type revert `PublicInputsLengthWrong()`; recovery costs another timelock delay.
///         Run this read-only check against the candidate before proposing it, from the commit
///         the deployed Oracle and router were built from.
///
///         The probe relies on the bb-generated `BaseZKHonkVerifier`, which checks the proof
///         length, then the public-input count, before any cryptography: an empty proof makes it
///         report the proof length it expects, and a zero proof of that length reaches the count
///         check. Any candidate that does not answer the first probe that way is refused.
///
/// Usage:
///   VERIFIER_CANDIDATE=0x... PROOF_TYPE=2 forge script script/CheckVerifierArity.s.sol --rpc-url $RPC_URL
contract CheckVerifierArity is Script {
    error CannotReadProofLength(address candidate);
    error ArityMismatch(address candidate, uint8 proofType, uint256 expectedInputs);

    bytes4 internal constant PROOF_LENGTH_WRONG_WITH_LOG_N =
        bytes4(keccak256("ProofLengthWrongWithLogN(uint256,uint256,uint256)"));
    bytes4 internal constant PUBLIC_INPUTS_LENGTH_WRONG = bytes4(keccak256("PublicInputsLengthWrong()"));

    function run() external view {
        address candidate = vm.envAddress("VERIFIER_CANDIDATE");
        uint8 proofType = uint8(vm.envUint("PROOF_TYPE"));
        uint256 expectedInputs = check(candidate, proofType);
        console.log("Candidate accepts the expected public-input count:", expectedInputs);
    }

    /// @notice Reverts unless `candidate` accepts `expectedPublicInputCount(proofType)` inputs.
    function check(address candidate, uint8 proofType) public view returns (uint256 expectedInputs) {
        expectedInputs = ProofTypes.expectedPublicInputCount(proofType);
        bytes32[] memory inputs = new bytes32[](expectedInputs);

        (bool ok, bytes memory ret) = candidate.staticcall(abi.encodeCall(IUltraVerifier.verify, ("", inputs)));
        // ProofLengthWrongWithLogN(logN, actualLength, expectedLength): selector + 3 words.
        if (ok || ret.length != 100 || bytes4(ret) != PROOF_LENGTH_WRONG_WITH_LOG_N) {
            revert CannotReadProofLength(candidate);
        }
        uint256 proofLength;
        assembly {
            proofLength := mload(add(ret, 100))
        }

        (ok, ret) = candidate.staticcall(abi.encodeCall(IUltraVerifier.verify, (new bytes(proofLength), inputs)));
        if (!ok && ret.length == 4 && bytes4(ret) == PUBLIC_INPUTS_LENGTH_WRONG) {
            revert ArityMismatch(candidate, proofType, expectedInputs);
        }
    }
}
