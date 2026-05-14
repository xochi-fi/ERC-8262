# Ethereum Magicians thread template

Copy the body below into a new topic at https://ethereum-magicians.org under the **ERCs** category. Suggested title and tags are at the top; remove them before pasting.

---

**Suggested title:** ERC: Zero-Knowledge Compliance Oracle (Xochi ZKP)

**Category:** ERCs

**Tags:** `erc`, `zk`, `privacy`, `compliance`, `oracle`

---

## Summary

We are drafting an ERC for an on-chain zero-knowledge compliance oracle. Users generate ZK proofs client-side that attest to compliance with jurisdiction-specific AML / sanctions / anti-structuring rules. Verifiers confirm validity on-chain. Transaction amounts, counterparty identities, and screening signals never leave the user's device.

Repository (reference implementation, contracts, Noir circuits, generated UltraHonk verifiers, test suite): https://github.com/xochi-fi/erc-xochi-zkp

Draft text: https://github.com/xochi-fi/erc-xochi-zkp/blob/main/erc-draft_xochi-zkp.md

We are opening this thread before filing the PR against `ethereum/ERCs` so the `discussions-to` frontmatter has a real URL, and to get early signal on the design before the editors triage it.

## Motivation

Public chains force a binary choice between transparency and privacy. Transparent execution leaks order flow to MEV. Privacy tools (Tornado Cash) have been sanctioned for lacking compliance mechanisms. Existing compromise approaches fall short:

- **View keys** (Railgun, Panther) reveal raw data to auditors on request -- delayed transparency.
- **TEE-based compliance** relies on hardware trust assumptions that have been broken repeatedly.
- **Compliance-by-exclusion** (Privacy Pools) proves you are NOT in a bad set. It does not prove you ARE compliant with specific jurisdiction rules.

This ERC proves compliance cryptographically at transaction time. The proof commits to screening results, jurisdiction thresholds, and provider attestations. Regulators verify a proof; they never see the underlying data.

## Scope

Eight proof types, each compiled as a separate Noir circuit with its own generated UltraHonk verifier:

| ID   | Name              | Purpose                                              |
| ---- | ----------------- | ---------------------------------------------------- |
| 0x01 | COMPLIANCE        | Jurisdiction-aware risk score below threshold        |
| 0x02 | RISK_SCORE        | Raw threshold / range proof (no jurisdiction)        |
| 0x03 | PATTERN           | Anti-structuring / velocity / round-amount analysis  |
| 0x04 | ATTESTATION       | Credential verification via Merkle inclusion         |
| 0x05 | MEMBERSHIP        | Inclusion in an authorized set                       |
| 0x06 | NON_MEMBERSHIP    | Exclusion from a sanctions list (sorted-tree adjacency) |
| 0x07 | COMPLIANCE_SIGNED | COMPLIANCE + in-circuit secp256k1 over signals       |
| 0x08 | RISK_SCORE_SIGNED | RISK_SCORE + in-circuit secp256k1 over signals       |

Two interfaces (`IXochiZKPVerifier`, `IXochiZKPOracle`) plus normative validation rules for each proof type, attestation TTL semantics, verifier versioning with revocation, and a per-jurisdiction "require signed signals" policy.

## Key design decisions we want feedback on

1. **Three trust tiers, explicit.** Self-attested (COMPLIANCE, RISK_SCORE) vs. provider-attested (signed variants) vs. credential-attested (ATTESTATION composed with the above). Strict-mode jurisdictions (US BSA, Singapore) reject the self-attested tier. We document this as a design tradeoff, not a bug. Is the boundary drawn in the right place?
2. **Eight separate circuits.** Each circuit has its own verifier contract behind a router. We considered a single circuit with a discriminant; we rejected it because the signed variants materially change the constraint set (in-circuit ECDSA) and we wanted unsigned-tolerant jurisdictions to skip that gas. Is the proliferation worth it?
3. **Verifier versioning + revocation.** Attestations record `verifierUsed` at submission time; `verifyProofAtVersion` re-runs against the historical verifier. Revoking a historical version makes `verifyProofAtVersion` revert but preserves the address (for audit). Current version is not revocable. Is this the right shape for retroactive proof-of-innocence?
4. **Chain / oracle binding in-circuit (signed variants only).** The signed variants include `chain_id` and `oracle_address` as public inputs covered by the ECDSA signature. Unsigned variants do not -- their replay guard is purely on-chain (`proofHash = keccak256(proof, proofType, block.chainid, address(this))`). Should the unsigned variants also bind in-circuit?
5. **`submitter == msg.sender`.** Every proof binds to its submitter at the public-input layer. We have a section on EIP-7702 / ERC-4337 / ERC-1271 interaction (account-abstraction wallets must surface the bound `submitter` before submission). Anything we missed?
6. **Provider weight publication.** Weights and configs are versioned on-chain via a config-hash registry with revocation. Current config is not revocable. Provider configuration history is bounded (reference: 256 entries). Should the bound be normative or implementation-defined?

## Reference implementation status

- 480 Solidity tests, 89 Noir tests, end-to-end TypeScript SDK tests (noir_js + bb.js + anvil + on-chain verify)
- Real proof fixtures for the six unsigned types; signed variants exercised in SDK tests (fresh ECDSA witness per run)
- Foundry, Solidity 0.8.28, Cancun EVM
- Nargo 1.0.0-beta.20, Barretenberg bb 4.0.0-nightly.20260120

## Related standards

- **ERC-3643 (T-REX):** complementary -- this ERC could serve as a ZK identity provider within a 3643 deployment.
- **Privacy Pools:** subset of this design -- set membership is one of our eight proof types.
- **EIP-7963:** narrower -- gates one token's transfers through one oracle with one proof type.
- **ERC-7812:** general-purpose private statement registry -- this ERC could operate as a compliance-specific registrar within it.
- **ERC-8039:** smart-account verifier ABI -- our per-type verifiers could be wrapped behind 8039 adapters.

Full Related Work section in the draft, including ERC-1922, ERC-8035/8036, EIP-7702, and VOSA-RWA.

## What we are NOT asking for here

- Number assignment (that is the editors' call on the PR).
- Status changes (it stays Draft until the editors decide).
- Approval of the reference implementation (this is an interface ERC, not a contract bake-off).

## Authors

- DROO ([@DROOdotFOO](https://github.com/DROOdotFOO))
- Bloo ([@bloo-berries](https://github.com/bloo-berries))

Both will be on this thread to respond.
