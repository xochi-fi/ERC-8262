// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IUltraVerifier} from "../../src/interfaces/IUltraVerifier.sol";

/// @dev Always returns true. Use when tests don't care about proof verification outcome.
contract PassingVerifier is IUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

/// @dev Always returns false. Use when tests need to assert a failed-verification path.
contract FailingVerifier is IUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return false;
    }
}

/// @dev Parameterized stub. Distinct from PassingVerifier/FailingVerifier because it reads
///      storage (different codehash), which matters for the router's codehash-pinning tests
///      that need fresh deployments with stable, predictable codehashes.
contract StubVerifier is IUltraVerifier {
    bool public shouldPass;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return shouldPass;
    }
}

/// @dev Regression: malicious verifier that attempts to mutate state from inside verify().
///      The IUltraVerifier interface declares verify() as `view`, so Solidity emits a
///      STATICCALL at the CALLER (XochiZKPVerifier) when invoking it. STATICCALL halts
///      on any SSTORE, LOG, CREATE, SELFDESTRUCT, or CALL with non-zero value -- the
///      EVM-level guarantee that protects the router from a malicious verifier.
///
///      Note: this contract intentionally does NOT inherit IUltraVerifier. Its verify()
///      function is declared non-view (writes to `counter`) so the compiler is happy.
///      The selector matches IUltraVerifier.verify, so the router can cast and call it.
///      At runtime the call is STATICCALL (per the interface used at the call site),
///      so the SSTORE fails and the entire call reverts.
contract MutatingVerifier {
    uint256 public counter;

    function verify(bytes calldata, bytes32[] calldata) external returns (bool) {
        counter += 1; // SSTORE under STATICCALL must revert
        return true;
    }
}
