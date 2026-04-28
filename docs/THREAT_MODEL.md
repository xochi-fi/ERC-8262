# Xochi ZKP Threat Model

This document describes who is trusted, what each role can do, what attacks are
in scope vs. out of scope, and how to respond to incidents.

Read this before integrating, deploying, or auditing.

---

## TL;DR

- **The cryptographic guarantees** assert that the published rule was computed correctly on inputs the user chose to disclose privately.
- **Signal and credential honesty** is anchored to provider-side commitments (registered config hashes; per-provider credentials Merkle roots), not to in-circuit signatures.
- **No single key is sufficient to drain or freeze the system.** Owner actions are timelocked; emergency response is segmented into instant pauses (per proof type) and delayed permanent state changes.
- **Treat attestations as evidence of correct computation, not as evidence of underlying truth** unless the integrator separately validates the inputs (e.g., insists on a specific provider, jurisdiction, threshold, or credential type).

---

## Roles and capabilities

### Oracle owner (timelocked admin)

Holds the `owner` key on `XochiZKPVerifier`, `XochiZKPOracle`, and (transitively) `SettlementRegistry`. In production deployments this MUST be a multisig behind `XochiTimelock`.

| Capability | Delay | Notes |
|---|---|---|
| Replace a verifier (`proposeVerifier` + `executeVerifierUpdate`) | 24 h | New verifier address must pass `code.length > 0` |
| Revoke a historical verifier version (timelocked path: `proposeVersionRevocation` + `executeVersionRevocation`) | 6 h | Affects `verifyProofAtVersion` only; live verifications use the current verifier |
| Revoke a historical verifier version (immediate emergency path: `revokeVerifierVersion`) | 0 | Documented as emergency-only; routine revocations should use the timelocked path |
| Pause a single proof type (`pauseProofType`) | 0 | Reversible, instant. Stops both `verifyProof` and `verifyProofAtVersion` |
| Pause all proof types (`pause`) | 0 | Reversible. Affects oracle and verifier independently |
| Update provider config (`updateProviderConfig`) | 6 h | Cannot re-register a previously revoked config (M-3) |
| Revoke a config (`revokeConfig`) | 6 h | Permanent: a revoked config cannot be re-registered |
| Register / revoke generic merkle root (membership / non-membership trees) | 6 h | Used for jurisdiction-managed sets like sanctions lists |
| Register / revoke reporting threshold (PATTERN proofs) | 6 h | Caller-supplied `reporting_threshold` must match a registered value |
| Set provider publisher EOA (`setProviderPublisher`) | 6 h | Authorizes a per-provider publisher; setting to `address(0)` disables the provider |
| Revoke a credential root (`revokeCredentialRoot`) | 0 | Owner can revoke any credential root; provider can revoke their own. Affects ATTESTATION proofs only |
| Transfer ownership (`transferOwnership`) | 24 h | Two-step accept; 48-hour acceptance deadline (`Ownable2Step`) |
| Update attestation TTL (`updateAttestationTTL`) | 6 h | Bounded by `[1 hour, 30 days]` |
| Compact config history (`compactConfigHistory`) | 24 h | Removes revoked entries from on-chain history; preserves current |

**What the owner CANNOT do:**

- Forge an attestation. The Oracle stores attestations only after `IUltraVerifier.verify` returns true.
- Override stored attestations. `_attestations[subject][jurisdictionId]` is overwritten on a *new* successful submission by the same subject; historical attestations remain queryable via `getHistoricalProof(proofHash)`.
- Re-register a permanently-revoked config hash (M-3) or reuse an `_usedProofs` entry.
- Bypass the per-chain proof replay check (`_usedProofs[proofHash]`).
- Mutate the verifier's behavior at runtime: `IUltraVerifier.verify` is `view`, so any STATICCALL re-entry that tries to write state reverts (regression: `test_staticcall_prevents_mutatingVerifier`).

### Provider publisher EOA (per provider)

A provider authority designated by the oracle owner via `setProviderPublisher(providerId, publisher)`. Each provider maintains an off-chain credentials Merkle tree and publishes new roots on-chain.

| Capability | Notes |
|---|---|
| Publish a new credential root (`publishCredentialRoot`) | Append-only; root TTL is 48 h (`CREDENTIAL_ROOT_TTL`) |
| Revoke their own credential root (`revokeCredentialRoot`) | Can be combined with publishing a new root that excludes specific credentials |

**What the provider CANNOT do:**

- Attest to credentials issued by a different provider (`provider_id` is bound into the credential hash and verified against the registry's `providerId` field).
- Bind a credential to anyone other than the credential's intended recipient (`submitter` is part of the credential hash).
- Take over Oracle admin functions (separate role).

### Submitter (end user / dApp)

Any EOA that submits a proof to the Oracle.

| Capability | Notes |
|---|---|
| Submit any proof for which they hold the witness | Proof verifies cryptographically against the registered verifier |
| Read attestations | All views are public |

**What the submitter CANNOT do:**

- Submit a proof on behalf of another address. The `submitter` field is a public input, bound to `msg.sender` by the Oracle.
- Replay a proof on the same chain. Each `(proof, proofType)` hash is single-use per chain.
- Forge a credential. ATTESTATION proofs require Merkle inclusion in the registered credentials tree; the leaf is bound to (provider, submitter, type, attribute, expiry) and the prover cannot construct an arbitrary leaf without a tree path.
- Lie about screening signals... this is documented as an explicit DESIGN tradeoff (see "Honest signals" below).

---

## What an attestation cryptographically guarantees

For any attestation stored on-chain (queryable via `getHistoricalProof(proofHash)`):

1. **Proof validity.** Some submitter ran the published circuit on private inputs and the Fiat–Shamir transcript hashed all public inputs + the verifier's `VK_HASH` into the challenge derivation (Frozen-Heart regression: `test_frozenHeart_*`).
2. **Public-input commitment.** The verifier's transcript binds the public inputs cryptographically; mutating any byte of the public inputs invalidates the proof (regression test included).
3. **Submitter binding.** The `submitter` public input equals `msg.sender` of the submission tx (`SubmitterMismatch` revert). For MEMBERSHIP / NON_MEMBERSHIP / ATTESTATION, the leaf format also binds the proven element to `submitter` in-circuit (audit fixes H-3, C-1).
4. **Replay protection.** Each `(proof, proofType)` may only be used once per Oracle deployment.
5. **Verifier provenance.** `attestation.verifierUsed` records the verifier address at submission time. Even if the verifier is later upgraded or revoked, `getHistoricalProof` still returns the original attestation; the *re-verification* path (`verifyProofAtVersion`) honors revocations.
6. **Per-circuit registry validation.** Each proof type's validator cross-checks public inputs against on-chain registries:
   - COMPLIANCE / RISK_SCORE: `config_hash` must be a current or historical (non-revoked) config.
   - PATTERN: `reporting_threshold` must be registered; `time_window >= MIN_TIME_WINDOW (3600s)`.
   - ATTESTATION: `credential_root` must be currently registered for the named `provider_id` and not expired.
   - MEMBERSHIP / NON_MEMBERSHIP: `merkle_root` must be in the generic registry.
   - All time-bound proofs: `current_timestamp` within `MAX_PROOF_AGE (1h)` of `block.timestamp`.

---

## What an attestation does NOT guarantee

### Honest screening signals (DESIGN, audit I-1)

The COMPLIANCE and RISK_SCORE circuits accept `signals[]` as private inputs and never verify a provider signature over them. A user could enter `signals = [0, 0, ...]` and produce a valid "low-risk" proof. The provider commitment (`provider_set_hash`, `config_hash`) only commits to *which* providers and weights — not to what those providers actually returned.

This is documented in the EIP draft and in `README.md` (Trust model section). It is the most important fact an integrator must understand: **ZK proves the computation, not the inputs.**

If integrators require signal honesty, they must layer an additional attestation on top — e.g., insist on an ATTESTATION proof from a specific provider in addition to the COMPLIANCE proof.

### Untargeted membership / non-membership

For trees with public contents (e.g., OFAC sanctions lists), MEMBERSHIP and NON_MEMBERSHIP proofs prove a fact about *the submitter* (audit H-3 binding). For private trees with per-user salts, the same holds, but the salt must be communicated by the tree publisher to each user.

If a tree publisher constructs leaves incorrectly (e.g., not binding to `submitter`), the resulting proofs are meaningless. Tree publishers are trusted to follow `leaf_hash_subject(submitter, set_id, salt)`.

### Cross-chain semantic equivalence

The proof itself contains no chain identifier. A proof that verifies on chain A also verifies on chain B if both chains have the same Verifier deployed and the same registry contents (config hash, merkle roots, credential roots, etc.). This is **by design**:

- The fact a proof asserts (compliance, risk, credential) is chain-independent.
- Each chain has its own `_usedProofs[proofHash]` storage, so per-chain replay protection still applies.
- Each chain has its own attestation record; a counterparty on chain B does not see chain A's attestation unless they query chain A directly.
- Each chain's per-circuit registries gate validity: a proof referencing config hash `H` only validates on chains where `H` is registered.

If an integrator wants strict chain-binding, they must include `chainId` in the credential payload off-chain (out-of-band), or insist on a provider-issued credential with chain-specific scope. Adding `chainId` as a circuit public input would require a redesign and re-generation of all six verifiers; this has not been done because the marginal value over per-chain registry validation is small.

### Future credential validity

ATTESTATION proofs assert the credential is in the registered tree at proof submission time and the expiry has not yet passed. They do NOT guarantee the credential will remain valid:

- The provider may publish a new root that excludes the credential (revocation).
- The credential may expire between submission and external use.
- The current credential root has a 48 h TTL; integrators relying on `verifyProofAtVersion` for retroactive lookup must understand that historical roots eventually fall out of the validity window.

### Soundness of the underlying cryptography

The system inherits the soundness assumptions of:

- **UltraHonk** (Aztec's PLONK derivative).
- **BN254 KZG trusted setup** (Aztec's powers-of-tau ceremony).
- **Pedersen hash on Baby Jubjub / BN254 curve** (preimage and collision resistance).
- **Noir compiler** (witness generation correctness).
- **`bb` Solidity verifier generator** (correct Fiat–Shamir transcript construction).

These are external dependencies. A soundness break in any of them invalidates attestations regardless of contract behavior. We track Aztec security advisories and pin toolchain versions.

---

## Attack scenarios in scope

### Compromised oracle owner key

**Impact.** Owner can:
- Replace verifiers (24 h delay), enabling forged attestations going forward.
- Mass-revoke historical verifier versions (6 h delay via `proposeVersionRevocation`, instant via `revokeVerifierVersion`), DoS-ing retroactive proof-of-innocence.
- Pause the system (instant), DoS-ing all submissions.
- Set malicious provider publishers (6 h delay), enabling fraudulent credential issuance.

**Mitigation.**
- Owner SHOULD be a multisig with geographically distributed signers.
- Owner SHOULD be `XochiTimelock` (which enforces the 6 h / 24 h delays at the timelock layer; the verifier's own `executeVerifierUpdate` adds an additional verifier-level delay).
- Monitoring on `VerifierProposed`, `VersionRevocationProposed`, `ProviderPublisherSet`, `Paused` events — anomalous activity should trigger guardian cancellation via `XochiTimelock.cancel`.
- The `revokeVerifierVersion` immediate path is documented as emergency-only; routine production usage should always go through `proposeVersionRevocation`.

### Compromised provider publisher key

**Impact.** Publisher can publish credential roots referencing fraudulent credentials (i.e., credentials that bind arbitrary submitters to arbitrary attributes).

**Mitigation.**
- Provider publishes via a hot-key EOA but maintains tree contents off-chain (IPFS) for audit.
- Owner can rotate the publisher EOA via `setProviderPublisher` (6 h timelock).
- Owner or publisher can revoke published roots (`revokeCredentialRoot`) immediately.
- Integrators can pin specific provider IDs and refuse to honor unknown providers.

### Soundness bug in a deployed verifier

**Impact.** Forged proofs that pass verification.

**Response runbook.**
1. **Immediately:** `pauseProofType(affectedType)` from the owner. This stops both new `submitCompliance` calls and re-verifications via `verifyProofAtVersion`.
2. **Within 24 h:** `proposeVerifier(affectedType, fixed)` — schedules the upgrade.
3. **24 h later:** `executeVerifierUpdate(affectedType)` — replaces the buggy verifier.
4. **Within 6 h:** `proposeVersionRevocation(affectedType, badVersion)` — schedules historical revocation.
5. **6 h later:** `executeVersionRevocation(affectedType, badVersion)` — finalizes revocation.
6. **Optional:** `unpauseProofType(affectedType)` once the new verifier is live.

**Note:** the immediate `revokeVerifierVersion` is available if waiting 6 h is unacceptable, but using it gives up the protection against malicious owner mass-revocation. Prefer the timelocked path unless the bug is being actively exploited *via re-verification* (which is rare — most exploits go through fresh submissions, which the pause already blocks).

### Frontend / RPC compromise

**Impact.** Adversary tricks user into signing a malicious tx (e.g., accepting ownership transfer to attacker).

**Mitigation.**
- All admin transitions are at minimum 6 h timelocked.
- `Ownable2Step` requires two-tx ownership transfer with 48 h acceptance window.
- Users (admins) verify pending state via `getPendingVerifier`, `getPendingRevocation`, `pendingOwner` before accepting.

### Generated verifier supply-chain attack

**Impact.** A compromised `bb` toolchain emits a backdoored Solidity verifier that accepts forged proofs.

**Mitigation.**
- `bb` and `nargo` versions are pinned in CI (see `Nargo.toml` / `package.json` / build docs).
- Generated verifier files are committed to the repo and reviewed manually on each regeneration.
- `VK_HASH` is recorded in each verifier and emitted by `bb`; it can be cross-validated against the compiled circuit JSON.
- Aztec security advisories are tracked.

### Excess ETH lock in `XochiTimelock` (closed)

The earlier audit finding L-1 is fixed: `execute` reverts on `msg.value != value`.

---

## Out of scope

The following are explicitly out of scope for this codebase. Integrators / operators must address them at higher layers:

1. **Front-end UX security.** The contracts assume the user understands what they sign. Wallet plugins, transaction simulators, and chain explorers are external.
2. **Off-chain credential issuance integrity.** Providers are trusted to issue real credentials. Their off-chain processes (KYC vendor, document review) are external.
3. **Privacy of submitter address.** Every attestation is linked to a submitter EOA. Mixers, stealth addresses, or relayers can obscure this; this codebase does not.
4. **Bridging attestations across chains.** Attestations are per-chain. Cross-chain attestation portability is an integrator concern.
5. **Sybil resistance.** Anyone can generate any proof for which they hold the witness. Per-user rate limiting is a higher-layer concern.
6. **Front-running of submissions.** The `submitter` binding to `msg.sender` prevents another party from claiming a user's proof, but does not prevent a copycat user from generating their *own* proof for the same statement.

---

## Invariants enforced by tests

The following invariants are protected by regression tests; breaking them indicates a security regression:

| Invariant | Test |
|---|---|
| Cross-type proof confusion blocked at verifier layer | `test_crossType_complianceProof_rejectedByRiskScoreVerifier`, `test_crossType_membershipProof_rejectedByNonMembershipVerifier` |
| STATICCALL prevents state mutation by malicious verifier | `test_staticcall_prevents_mutatingVerifier` |
| Public input length validated (count + 32-byte alignment) | `test_verifyProof_revert_wrongPublicInputCount`, fuzz tests in `LibraryFuzz.t.sol` |
| Logical input count matches each verifier's `vk.publicInputsSize - PAIRING_POINTS_SIZE` | `test_invariant_logicalInputCount_matchesAllVerifiers` |
| Frozen-Heart: tampering with public inputs invalidates proofs | `test_frozenHeart_*_publicInputMutation` (×6) |
| Frozen-Heart: tampering with proof bytes invalidates proofs | `test_frozenHeart_proofMutation_compliance` |
| `Ownable2Step` 48 h transfer deadline | `test_transferOwnership_revert_expired` |
| Per-type proof replay protection | existing `_usedProofs` tests |
| Permanent config revocation (M-3) | `test_updateProviderConfig_revert_reRegisterRevoked` |
| Non-membership leaf adjacency (H-4) | `test_main_revert_non_adjacent_brackets` (Noir) |
| ATTESTATION cross-submitter forgery blocked (C-1 + H-3) | `test_main_revert_wrong_submitter` (Noir) |
| RISK_SCORE trivial bounds rejected (H-1) | `test_submitCompliance_revert_riskScore_*` family |
| PATTERN analysis_type bound to STRUCTURING for SettlementRegistry (H-2) | `test_finalizeTrade_revert_velocityAnalysisRejected`, `test_finalizeTrade_revert_publicInputsMismatch` |
| Credential root TTL window (Phase 1 infra) | `test_credentialRoot_expiresAfterTTL`, `test_credentialRoot_overlapWindow` |

---

## Open items (post-audit follow-ups)

These do not block deployment but should be tracked:

- Provider Issuance Protocol HTTP spec + reference SDK (UX work, separate stream).
- TS `CredentialClient` SDK for path resolution and root rotation handling.
- Per-provider revocation Merkle tree (currently revocation requires republishing the credentials tree without the bad leaf; a non-membership-based revocation tree would allow per-credential revocation without rebuilding).
- Deployment scripts (`script/`) updated to set up provider publishers as part of bootstrap.
- Toolchain version pinning enforcement in CI.
