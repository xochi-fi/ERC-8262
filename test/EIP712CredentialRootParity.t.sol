// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {EIP712CredentialRoot} from "../src/libraries/EIP712CredentialRoot.sol";

/// @notice Byte-for-byte parity test between the Solidity EIP-712 digest and
///         the TypeScript digest computed by `xochi-sdk/src/provider/eip712.ts`.
///         If either side drifts, both this test and the matching vitest at
///         `xochi-sdk/test/eip712-credential-root.test.ts` will fail.
///
///         The hardcoded vector below is the value the TS test logs to stdout:
///         `[parity] credential_root_digest = 0x...`. Regenerate via
///         `npx vitest run test/eip712-credential-root.test.ts --reporter=verbose`
///         and paste the value here if the format ever changes.
contract EIP712CredentialRootParityTest is Test {
    address constant ORACLE_ADDRESS = 0x1234567890123456789012345678901234567890;
    uint256 constant CHAIN_ID = 31337; // foundry default

    // Fixture inputs matching the SAMPLE constant in the vitest file.
    uint256 constant SAMPLE_PROVIDER_ID = 42;
    bytes32 constant SAMPLE_ROOT = 0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd;
    uint64 constant SAMPLE_NOT_BEFORE = 1700000000;
    uint64 constant SAMPLE_NOT_AFTER = 1700003600;

    function test_parity_credentialRootDigest() public {
        vm.chainId(CHAIN_ID);

        bytes32 cidHash = keccak256(bytes("ipfs://Qm-test"));
        bytes32 domainSep = EIP712CredentialRoot.buildDomainSeparator(ORACLE_ADDRESS);
        bytes32 digest = EIP712CredentialRoot.toTypedDataHash(
            domainSep, SAMPLE_PROVIDER_ID, SAMPLE_ROOT, cidHash, SAMPLE_NOT_BEFORE, SAMPLE_NOT_AFTER
        );

        // PARITY_VECTOR computed under EIP-712 domain name "ERC8262Oracle".
        // The SDK at xochi-sdk/src/provider/eip712.ts must use the same domain
        // name to match -- see xochi-sdk/HANDOFF.md.
        bytes32 expected = 0x82109ef42010d7a55f19c7b22fb75d1ebf990ec91663fc8c7fa9dd13ead2b3dd;
        assertEq(digest, expected, "EIP-712 digest drift between Solidity and xochi-sdk/eip712.ts");
    }

    function test_parity_emptyCidHash() public pure {
        // keccak256("") matches the value the TS `cidHash("")` returns.
        bytes32 expected = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        assertEq(keccak256(bytes("")), expected);
    }
}
