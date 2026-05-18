// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ERC8262Verifier} from "../../src/ERC8262Verifier.sol";
import {ProofTypes} from "../../src/libraries/ProofTypes.sol";

/// @dev Shared base for ERC8262Verifier and ERC8262Oracle test suites.
///      Provides common EOAs, a dummy proof of the size bb-generated verifiers expect,
///      and a registration helper that wires a single stub verifier into every proof type.
abstract contract ERC8262TestBase is Test {
    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");

    /// @dev bb-generated verifiers expect a 2144-byte proof. The bytes themselves are
    ///      irrelevant when a stub verifier is in place; only the length matters for the
    ///      input-alignment checks in the router.
    function _dummyProof() internal pure returns (bytes memory) {
        return new bytes(2144);
    }

    /// @dev Registers `stub` as the verifier for every valid proof type on `v`.
    ///      Pass `includeSigned = true` to also cover COMPLIANCE_SIGNED, RISK_SCORE_SIGNED,
    ///      and COMPLIANCE_MULTI_SIGNED -- needed by the Oracle suite, optional for tests
    ///      that only exercise the unsigned routing path.
    function _registerAllVerifiers(ERC8262Verifier v, address stub, bool includeSigned) internal {
        vm.startPrank(owner);
        v.setVerifierInitial(ProofTypes.COMPLIANCE, stub);
        v.setVerifierInitial(ProofTypes.RISK_SCORE, stub);
        v.setVerifierInitial(ProofTypes.PATTERN, stub);
        v.setVerifierInitial(ProofTypes.ATTESTATION, stub);
        v.setVerifierInitial(ProofTypes.MEMBERSHIP, stub);
        v.setVerifierInitial(ProofTypes.NON_MEMBERSHIP, stub);
        if (includeSigned) {
            v.setVerifierInitial(ProofTypes.COMPLIANCE_SIGNED, stub);
            v.setVerifierInitial(ProofTypes.RISK_SCORE_SIGNED, stub);
            v.setVerifierInitial(ProofTypes.COMPLIANCE_MULTI_SIGNED, stub);
        }
        vm.stopPrank();
    }
}
