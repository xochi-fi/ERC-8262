# ERC-8262 (Xochi ZKP) Threat Model

Who is trusted, what each role can do, which attacks are in scope, and how to
respond to incidents. Covers the reference implementation of [ERC-8262](../ERC-8262.md)
([ethereum/ERCs PR #1747](https://github.com/ethereum/ERCs/pull/1747)).

---

## TL;DR

- The cryptographic guarantees say the published rule was computed correctly on inputs the user chose to keep private. They do not say the inputs were honest.
- Credential honesty: anchored at publish time. The provider's signing key (HSM/KMS-resident, distinct from the publisher EOA) signs the credential root via EIP-712; the Oracle verifies the signature on-chain via `ecrecover` before storing the root. A compromised publisher EOA cannot mint forged credentials without also holding the signing key.
- Signal honesty: unsigned COMPLIANCE / RISK_SCORE pass that responsibility to the integrator; COMPLIANCE_SIGNED and RISK_SCORE_SIGNED verify a registered provider's secp256k1 signature in-circuit. `JurisdictionConfig.requireSignedSignals` rejects the unsigned variants for US BSA and Singapore.
- No single key drains or freezes the system. Owner actions are timelocked. Emergencies use instant per-proof-type pauses; permanent state changes wait.
- An attestation is evidence of correct computation, not of underlying truth. If the integration depends on the latter, the integrator picks the signed variant, pins a specific provider, or layers something else on top.

---

## Roles and capabilities

### Oracle owner (timelocked admin)

Holds the `owner` key on `XochiZKPVerifier`, `XochiZKPOracle`, and (transitively) `SettlementRegistry`. In production deployments this MUST be a multisig behind `XochiTimelock`.

| Capability                                                                                                      | Delay | Notes                                                                                                |
| --------------------------------------------------------------------------------------------------------------- | ----- | ---------------------------------------------------------------------------------------------------- |
| Replace a verifier (`proposeVerifier` + `executeVerifierUpdate`)                                                | 24 h  | New verifier address must pass `code.length > 0`; `expectedCodehash` is pinned at proposal time and re-checked on execute |
| Revoke a historical verifier version (timelocked path: `proposeVersionRevocation` + `executeVersionRevocation`) | 6 h   | Affects `verifyProofAtVersion` only; live verifications use the current verifier                     |
| Revoke a historical verifier version (immediate emergency path: `revokeVerifierVersion`)                        | 0     | Documented as emergency-only; routine revocations should use the timelocked path                     |
| Pause a single proof type (`pauseProofType`)                                                                    | 0     | Reversible, instant. Stops both `verifyProof` and `verifyProofAtVersion`                             |
| Pause all proof types (`pause`)                                                                                 | 0     | Reversible. Affects oracle and verifier independently                                                |
| Update provider config (`updateProviderConfig(bytes32,string,uint256[])`)                                       | 6 h   | Atomically writes the provider expansion alongside the new config hash (audit F-2 closure). Cannot re-register a previously revoked config. |
| Revoke a config (`revokeConfig`)                                                                                | 6 h   | Permanent: a revoked config cannot be re-registered                                                  |
| Register / revoke generic merkle root (membership / non-membership trees)                                       | 6 h   | Used for jurisdiction-managed sets like sanctions lists                                              |
| Register / revoke reporting threshold (PATTERN proofs)                                                          | 6 h   | Caller-supplied `reporting_threshold` must match a registered value                                  |
| Set provider publisher EOA (`setProviderPublisher`)                                                             | 6 h   | Authorizes a per-provider publisher; setting to `address(0)` disables the provider                   |
| Revoke a credential root (`revokeCredentialRoot`)                                                               | 0     | Owner can revoke any credential root; provider can revoke their own. Affects ATTESTATION proofs only |
| Transfer ownership (`transferOwnership`)                                                                        | 24 h  | Two-step accept; 48-hour acceptance deadline (`Ownable2Step`)                                        |
| Update attestation TTL (`updateAttestationTTL`)                                                                 | 6 h   | Bounded by `[1 hour, 30 days]`                                                                       |
| Compact config history (`compactConfigHistory`)                                                                 | 24 h  | Removes revoked entries from on-chain history; preserves current                                     |

**What the owner CANNOT do:**

- Forge an attestation. The Oracle stores attestations only after `IUltraVerifier.verify` returns true.
- Override stored attestations. `_attestations[subject][jurisdictionId]` is overwritten on a _new_ successful submission by the same subject; historical attestations remain queryable via `getHistoricalProof(proofHash)`.
- Re-register a permanently-revoked config hash or reuse an `_usedProofs` entry.
- Bypass the per-chain proof replay check (`_usedProofs[proofHash]`).
- Mutate the verifier's behavior at runtime: `IUltraVerifier.verify` is `view`, so any STATICCALL re-entry that tries to write state reverts (regression: `test_staticcall_prevents_mutatingVerifier`).

### Provider publisher EOA (per provider)

A provider authority designated by the oracle owner via `setProviderPublisher(providerId, publisher)`. The publisher submits the publish tx but does not authorize its contents. A separate signing key (see "Credential signing key" role below) signs the EIP-712 `CredentialRootPublication` struct, and the Oracle verifies that signature on-chain.

| Capability                                                | Notes                                                                         |
| --------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Submit `publishCredentialRoot(providerId, root, cid, notBefore, notAfter, signature)` | Must present a signature from `_credentialSigner[providerId]`; append-only; root TTL 48 h (`CREDENTIAL_ROOT_TTL`) |
| Revoke their own credential root (`revokeCredentialRoot`) | Can be combined with publishing a new root that excludes specific credentials |

**What the publisher CANNOT do alone:**

- Mint a credential root with arbitrary contents. The publish tx reverts unless the EIP-712 signature recovers to the registered credential signer.
- Attest to credentials issued by a different provider (`provider_id` is bound into both the signed publication struct and the credential hash).
- Bind a credential to anyone other than the credential's intended recipient (`submitter` is part of the credential hash).
- Take over Oracle admin functions (separate role).

### Credential signing key (per provider)

A second per-provider authority distinct from the publisher EOA. The signing key signs `CredentialRootPublication { providerId, root, cidHash, notBefore, notAfter }` per EIP-712. Held in HSM/KMS in a sane production setup. Registered via `setCredentialSigner(providerId, signer)` (REGISTRAR role).

| Capability                                                                                | Notes                                                                                  |
| ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Sign a `CredentialRootPublication` for any (root, cid) on the publisher's queue           | The signature is the on-chain authority for the tree contents; the publisher cannot bypass it |
| Constrain replay via `notBefore` / `notAfter`                                             | Independent of `CREDENTIAL_ROOT_TTL`; the window bounds the signature, not the published root |

**What a compromised signing key allows:**

- Mint signed `CredentialRootPublication`s for arbitrary (root, cid) pairs the attacker chooses. If the publisher EOA is honest, the publisher can refuse to broadcast; if the publisher is also compromised, both keys are needed and one defense is gone.
- Does NOT allow reusing an old signature for a new root: the signed struct binds (root, cidHash, notBefore, notAfter); changing any field breaks `ecrecover`.

**Mitigations:**

- Owner rotates via `setCredentialSigner(providerId, newSigner)`. New signatures must come from the new key. Roots already published under the old key remain provable until TTL or explicit revocation.
- Emergency disable: `setCredentialSigner(providerId, address(0))` blocks all future publishes for that provider. Combine with `revokeCredentialRoot(suspectRoot)` for any roots already on-chain that may have been signed by the compromised key.
- Two-key separation: in production, the publisher EOA and the signing key are held by different teams or in different HSMs. An attacker needs both to forge.

### Provider signing daemon (per signer key)

A provider that signs screening payloads for COMPLIANCE_SIGNED / RISK_SCORE_SIGNED proofs runs a daemon holding a secp256k1 private key. The daemon's `signer_pubkey_hash` is registered on-chain via `registerSignerPubkeyHash(bytes32)` (REGISTRAR role). The reference implementation lives at `xochi-sdk/daemon/`.

| Capability                            | Notes                                                                          |
| ------------------------------------- | ------------------------------------------------------------------------------ |
| Sign a screening payload (`POST /sign`) | Returns `(signature, pubkeyX, pubkeyY, signerPubkeyHash, payloadHash)`        |
| Refuse a duplicate sign request        | Replay-DB rejects identical `(submitter, payloadHash)`; modeled on Vouch/Dirk   |

**What the signing daemon CANNOT do:**

- Forge an attestation. The signature only proves that signals were attested by this signer; the proof still has to verify in-circuit and clear the Oracle's other checks.
- Bypass the Oracle registry. If the daemon's `signer_pubkey_hash` is not in `_validSignerPubkeyHashes`, every signed proof reverts at the Oracle.
- Sign for a provider that has been revoked. Owner calls `revokeSignerPubkeyHash` and any in-flight proofs from that key revert immediately.

**What a compromised signing key allows:**

- Mint signed COMPLIANCE_SIGNED / RISK_SCORE_SIGNED proofs with arbitrary signal values until the hash is revoked.
- Does NOT allow forging proofs for a different submitter. `submitter` is bound into the signed payload, and the Oracle separately enforces `submitter == msg.sender`.

Mitigations: keys held in HSM/KMS via `KeyLoader` interface (the dev `HexKeyLoader` is not for production); `revokeSignerPubkeyHash` on suspicion of compromise; threshold signing (FROST-secp256k1) is tracked as V2.

### Submitter (end user / dApp)

Any EOA that submits a proof to the Oracle.

| Capability                                       | Notes                                                            |
| ------------------------------------------------ | ---------------------------------------------------------------- |
| Submit any proof for which they hold the witness | Proof verifies cryptographically against the registered verifier |
| Read attestations                                | All views are public                                             |

**What the submitter CANNOT do:**

- Submit a proof on behalf of another address. The `submitter` field is a public input, bound to `msg.sender` by the Oracle.
- Replay a proof on the same chain. Each `(proof, proofType, chainId, oracle)` hash is single-use per deployment.
- Forge a credential. ATTESTATION proofs require Merkle inclusion in the registered credentials tree; the leaf is bound to (provider, submitter, type, attribute, expiry) and the prover cannot construct an arbitrary leaf without a tree path.
- Lie about screening signals **for the signed variants**. COMPLIANCE_SIGNED / RISK_SCORE_SIGNED verify a registered provider's secp256k1 signature over `(chain_id, oracle_address, provider_set_hash, signals, weights, timestamp, submitter)` in-circuit; the prover cannot fabricate signals without forging an ECDSA signature. Audit F-6: `chain_id` and `oracle_address` bind the digest to a specific deployment so the same signature cannot be replayed across chains or alternate Oracle deployments.
- Submit unsigned COMPLIANCE / RISK_SCORE in jurisdictions where `JurisdictionConfig.requireSignedSignals` is true (US, Singapore). The Oracle reverts with `SignedSignalsRequired` before any cryptographic work.

In permissive jurisdictions (EU, UK), the unsigned variants accept whatever signals the user supplies. Signal honesty there is the integrator's problem.

---

## What an attestation cryptographically guarantees

For any attestation stored on-chain (queryable via `getHistoricalProof(proofHash)`):

1. **Proof validity.** Some submitter ran the published circuit on private inputs and the Fiat–Shamir transcript hashed all public inputs + the verifier's `VK_HASH` into the challenge derivation (Frozen-Heart regression: `test_frozenHeart_*`).
2. **Public-input commitment.** The verifier's transcript binds the public inputs cryptographically; mutating any byte of the public inputs invalidates the proof (regression test included).
3. **Submitter binding.** The `submitter` public input equals `msg.sender` of the submission tx (`SubmitterMismatch` revert). For MEMBERSHIP / NON_MEMBERSHIP / ATTESTATION, the leaf format also binds the proven element to `submitter` in-circuit.
4. **Replay protection.** Each `(proof, proofType)` may only be used once per Oracle deployment.
5. **Verifier provenance.** `attestation.verifierUsed` records the verifier address at submission time. Even if the verifier is later upgraded or revoked, `getHistoricalProof` still returns the original attestation; the _re-verification_ path (`verifyProofAtVersion`) honors revocations.
6. **Per-circuit registry validation.** Each proof type's validator cross-checks public inputs against on-chain registries:
   - COMPLIANCE / RISK_SCORE: `config_hash` must be a current or historical (non-revoked) config.
   - COMPLIANCE_SIGNED / RISK_SCORE_SIGNED: same as above, plus `signer_pubkey_hash` must be in `_validSignerPubkeyHashes`. The Oracle also enforces `JurisdictionConfig.requireSignedSignals(jurisdictionId)`. Strict jurisdictions reject the unsigned variants.
   - PATTERN: `reporting_threshold` must be registered; `time_window >= MIN_TIME_WINDOW (3600s)`.
   - ATTESTATION: `credential_root` must be currently registered for the named `provider_id` and not expired.
   - MEMBERSHIP / NON_MEMBERSHIP: `merkle_root` must be in the generic registry.
   - All time-bound proofs: `current_timestamp` within `MAX_PROOF_AGE (1h)` of `block.timestamp`.

---

## What an attestation does NOT guarantee

### Honest screening signals

The unsigned COMPLIANCE (0x01) and RISK_SCORE (0x02) circuits accept `signals[]` as private inputs and never verify a provider signature. A user can submit `signals = [0, 0, ...]` and produce a valid "low-risk" proof. The provider commitment (`provider_set_hash`, `config_hash`) only commits to which providers and weights, not to what those providers returned.

**The signed variants close this gap.** COMPLIANCE_SIGNED (0x07) and RISK_SCORE_SIGNED (0x08):

- Verify an in-circuit secp256k1 ECDSA signature over a Pedersen digest of `(chain_id, oracle_address, provider_set_hash, signals, weights, timestamp, submitter)`. The signer cannot be substituted: `signer_pubkey_hash` is a public input, validated by the Oracle against `_validSignerPubkeyHashes`. The `chain_id` and `oracle_address` fields (audit F-6) anchor the signature to one deployment -- replay across chains or alternate Oracles requires forging a new signature.
- Bind the submitter into the signed payload. A relayer cannot steal a signed bundle and submit it under a different address; the in-circuit ECDSA verify fails.
- Are mandatory in strict jurisdictions. `JurisdictionConfig.requireSignedSignals(US) == true` and `requireSignedSignals(SG) == true`; the Oracle reverts with `SignedSignalsRequired` if a caller submits the unsigned variants for those jurisdictions. Permissive jurisdictions (EU, UK) accept either; integrators that care about signal honesty there should pick the signed variant explicitly.

Off-chain, providers run a signing daemon (reference implementation at `xochi-sdk/daemon/`) holding the secp256k1 key. The daemon's `signer_pubkey_hash` is registered once on-chain via `XochiZKPOracle.registerSignerPubkeyHash(bytes32)`. Provider key rotation is `revokeSignerPubkeyHash` followed by `registerSignerPubkeyHash` for the new key.

**Multi-provider quorum (COMPLIANCE_MULTI_SIGNED, 0x09).** Reduces single-provider trust to M-of-N. A single signed proof bundles up to `MAX_PROVIDERS_MULTI = 5` parallel signer slots; each active slot independently verifies a secp256k1 signature over a slot-specific Pedersen digest (distinct `DOMAIN_MULTI_SIGNED_SIGNALS` tag plus `slot_index` to prevent cross-proof and cross-slot replay), and each active slot independently asserts the per-provider risk score is below the jurisdiction high-risk floor. The Oracle additionally enforces `threshold_m >= JurisdictionConfig.minMultiProviderThreshold(jurisdictionId)` (US/SG require >= 2 distinct signers; EU/UK accept >= 1). Forging an attestation requires compromising at least `M` of the `N` registered signing keys simultaneously; with M=2, two independent provider compromises are needed.

For the unsigned variants in permissive jurisdictions, the original tradeoff still holds: ZK proves the computation, not the inputs. Integrators who require signal honesty there should either use the signed variant or layer an ATTESTATION proof from a specific provider on top.

### Untargeted membership / non-membership

For trees with public contents (e.g., OFAC sanctions lists), MEMBERSHIP and NON_MEMBERSHIP proofs prove a fact about _the submitter_. For private trees with per-user salts, the same holds, but the salt must be communicated by the tree publisher to each user.

If a tree publisher constructs leaves incorrectly (e.g., not binding to `submitter`), the resulting proofs are meaningless. Tree publishers are trusted to follow `leaf_hash_subject(submitter, set_id, salt)`.

### Cross-chain semantic equivalence

The chain-binding story splits cleanly along the signed/unsigned axis.

**Unsigned variants (COMPLIANCE, RISK_SCORE, PATTERN, ATTESTATION, MEMBERSHIP, NON_MEMBERSHIP).** The circuit itself contains no chain identifier. A proof that verifies on chain A also verifies on chain B if both chains have the same verifier deployed and the same registry contents (config hash, merkle roots, credential roots, etc.). This is **by design**:

- The fact a proof asserts (compliance, risk, credential) is chain-independent.
- Each chain has its own `_usedProofs[proofHash]` storage with `proofHash = keccak256(proof, proofType, block.chainid, address(this))`, so per-(chain, Oracle) replay-into-storage is still blocked.
- Each chain has its own attestation record; a counterparty on chain B does not see chain A's attestation unless they query chain A directly.
- Each chain's per-circuit registries gate validity: a proof referencing config hash `H` only validates on chains where `H` is registered.

If an integrator wants strict chain-binding for an unsigned proof type, they must include `chainId` in the credential payload off-chain (out-of-band), or insist on a provider-issued credential with chain-specific scope. The marginal value of in-circuit chain binding over per-chain registry validation was judged small for the unsigned variants and has not been done.

**Signed variants (COMPLIANCE_SIGNED, RISK_SCORE_SIGNED).** Audit F-6 closed the equivalent gap mathematically. The in-circuit Pedersen digest binds (`chain_id`, `oracle_address`, `provider_set_hash`, `signals`, `weights`, `timestamp`, `submitter`), and the secp256k1 ECDSA verification of the provider's signature happens over that digest. The Oracle additionally enforces `chain_id == block.chainid` and `oracle_address == address(this)` on every signed-variant submission. Replaying a signed proof against a different chain or against an alternate Oracle deployment on the same chain therefore requires forging a new ECDSA signature under the registered provider's key.

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
- **secp256k1 ECDSA** (used by COMPLIANCE_SIGNED / RISK_SCORE_SIGNED for in-circuit provider-signature verification, and by the Oracle for `ecrecover`-based credential-root signature verification at publish time).
- **Noir compiler** (witness generation correctness).
- **`bb` Solidity verifier generator** (correct Fiat–Shamir transcript construction).

These are external dependencies. A soundness break in any of them invalidates attestations regardless of contract behavior. We track Aztec security advisories and pin toolchain versions.

### Post-quantum considerations

Every primitive listed above rests on the hardness of discrete log in elliptic-curve groups (BN254 for the SNARK, Grumpkin for Pedersen, secp256k1 for ECDSA). All are broken in polynomial time by Shor's algorithm on a cryptographically-relevant quantum computer (CRQC). The current stack is therefore **pre-quantum** — and so is the rest of the Ethereum L1 + L2 ZK ecosystem (Linea, Scroll, Aztec, zkSync, Polygon zkEVM all use pairing-based SNARKs as of 2026).

We are **not engineering for PQ resistance in this draft**. Mainstream estimates put a CRQC capable of breaking these schemes 10-20 years out; the entire Ethereum ecosystem will migrate together via coordinated hard forks.

**Migration path (when the ecosystem moves):**

- **ZK proof system.** Swap UltraHonk for a hash-based / FRI-based system with no trusted setup: Plonky3, STARKs (Cairo, Stwo), or successors. This is a circuit recompilation + new generated verifier per proof type — mechanically identical to a circuit upgrade today. Each new verifier registers via `proposeVerifier` + `executeVerifierUpdate`; old verifiers get revoked via the existing version-revocation pipeline. No interface change visible to integrators.
- **In-circuit hash.** Pedersen → a SNARK-friendly hash that survives PQ context (Poseidon2 over a PQ-friendly field, or hash-based commitments). Affects every leaf and digest; coordinated fork.
- **In-circuit signature (for COMPLIANCE_SIGNED / ATTESTATION future signature variants).** Replace ECDSA-secp256k1 verify with hash-based signatures (SPHINCS+, XMSS). New `signer_pubkey_hash` registry keyed on the new scheme; old hashes revoked.
- **Off-chain provider keys.** Providers rotate from secp256k1 to PQ keys; the registry is curve-agnostic so this is an operational rotation, not a contract change.

**Today's hedge.** The architecture already separates "what is verified" (the on-chain verifier) from "what is registered" (per-type registries with revocation). A PQ migration reduces to: deploy new verifiers, register new keys/roots, revoke old. No data model change; no new audit surface. The cost of deferring PQ work is bounded by this migration shape.

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

**Impact.** Publisher cannot mint credential roots alone. `publishCredentialRoot` reverts unless the call carries an EIP-712 signature from `_credentialSigner[providerId]`, which the publisher does not hold. A compromised publisher can replay valid signatures within their (notBefore, notAfter) window for roots that have not yet been broadcast, but cannot create new signatures over malicious content.

**Worst case for publisher-only compromise:** the attacker submits a signed publication that the legitimate signer authorized but the legitimate publisher had not broadcast yet. If the signer's window is short (minutes, not days), this is bounded.

**Mitigation.**

- Two-key separation enforced on-chain. Publisher and credential signer are different addresses; both must be compromised for credential forgery.
- Owner can rotate the publisher EOA via `setProviderPublisher` (6 h timelock); existing published roots remain provable.
- Owner or publisher can revoke published roots (`revokeCredentialRoot`) immediately.
- Integrators can pin specific provider IDs and refuse to honor unknown providers.

### Compromised credential signing key

**Impact.** Attacker can mint signed `CredentialRootPublication` structs authorizing arbitrary trees. If the publisher EOA is honest, the attacker still needs the publisher to broadcast; if both are compromised, credential forgery is possible until the signer is revoked.

**Mitigation.**

- Keys held in HSM/KMS via the SDK's `KeyLoader` interface (the dev `HexKeyLoader` is unsafe). Compromise requires extracting from the HSM, raising the bar significantly.
- `setCredentialSigner(providerId, address(0))` instantly blocks all future publishes for that provider; existing roots that may have been signed by the compromised key get revoked individually via `revokeCredentialRoot`.
- Rotation: `setCredentialSigner(providerId, newSigner)` activates the new key for all subsequent publishes. No TTL on rotation; takes effect with the next REGISTRAR-role call.
- Threshold signing (FROST-secp256k1) is tracked as V2 for providers that need to split custody of the signing key.

### Soundness bug in a deployed verifier

**Impact.** Forged proofs that pass verification.

**Response runbook.** Codified end-to-end as `test/Incident_VerifierSoundness.t.sol` (audit F-7); the test asserts the full sequence below plus the negative-control cases (`cannotRevokeCurrentVersion`, surgical-pause, global-pause).

1. **Immediately:** `pauseProofType(affectedType)` from the owner. This stops both new `submitCompliance` calls and re-verifications via `verifyProofAtVersion`.
2. **Within 24 h:** `proposeVerifier(affectedType, fixed)` — schedules the upgrade.
3. **24 h later:** `executeVerifierUpdate(affectedType)` — replaces the buggy verifier.
4. **Within 6 h:** `proposeVersionRevocation(affectedType, badVersion)` — schedules historical revocation.
5. **6 h later:** `executeVersionRevocation(affectedType, badVersion)` — finalizes revocation.
6. **Optional:** `unpauseProofType(affectedType)` once the new verifier is live.

**Note:** the immediate `revokeVerifierVersion` is available if waiting 6 h is unacceptable, but using it gives up the protection against malicious owner mass-revocation. Prefer the timelocked path unless the bug is being actively exploited _via re-verification_ (which is rare — most exploits go through fresh submissions, which the pause already blocks).

### Frontend / RPC compromise

**Impact.** Adversary tricks user into signing a malicious tx (e.g., accepting ownership transfer to attacker).

**Mitigation.**

- All admin transitions are at minimum 6 h timelocked.
- `Ownable2Step` requires two-tx ownership transfer with 48 h acceptance window.
- Users (admins) verify pending state via `getPendingVerifier`, `getPendingRevocation`, `pendingOwner` before accepting.

### Generated verifier supply-chain attack

**Impact.** A compromised `bb` toolchain emits a backdoored Solidity verifier that accepts forged proofs.

**Mitigation.**

- `bb` and `nargo` versions are pinned in `.tool-versions` (read by mise/asdf) and verified by `make check-toolchain`. `make fixtures` depends on `check-toolchain` so a regeneration with mismatched versions fails fast locally; CI runs `scripts/parity-check.py` (audit F-8) on every PR to assert that the circuit's logical public-input arity matches the generated verifier's `NUMBER_OF_PUBLIC_INPUTS - 16` and the Solidity expectation.
- Generated verifier files are committed to the repo and reviewed manually on each regeneration.
- `VK_HASH` is recorded in each verifier and emitted by `bb`; it can be cross-validated against the compiled circuit JSON.
- Aztec security advisories are tracked.

---

## Practical limitations and adoption dependencies

The math works. The assumptions might not. What follows is a list of dependencies on the world outside the contracts: providers, regulators, operators, users, time. None of these are bugs in the codebase. All of them can sink the product.

### Provider adoption is required for the signed variants to be operational

COMPLIANCE_SIGNED / RISK_SCORE_SIGNED only matter when a real screening provider runs a signing daemon and registers a `signer_pubkey_hash`. No major AML provider (Chainalysis, TRM, Elliptic) currently signs screening data. The signed variants are primitives waiting for adoption. The reference daemon at `xochi-sdk/daemon/` is the shape an opt-in provider would deploy; getting them to deploy it is a business problem, not an engineering one.

A deployment in strict-mode jurisdictions (US, Singapore) without a registered signing key fails closed: every signed-variant submission reverts at `_validSignerPubkeyHashes`, and the unsigned path is already off. Failing closed is correct. It still means no compliance evidence gets recorded.

### Regulatory acceptance is unresolved

Whether US BSA, EU MiCA, FATF Travel Rule, or any national regulator accepts a ZK proof as compliance evidence is a legal question this codebase does not answer. The EIP draft mentions VARA's "anonymity-enhanced crypto" definition; that is the only regulatory anchor we have today. Anyone using these attestations as filing evidence in a regulated context needs legal review first. The codebase delivers cryptographic primitives. Whether enforcement bodies recognize them is a separate dependency, and the entire value proposition rests on it.

### PATTERN proofs are still self-attested

The signed-variant fix does not extend to PATTERN. The circuit consumes a private `(amounts[], timestamps[])` array the user supplies, and no provider in the system signs full address-level transaction histories. A user can cherry-pick clean transactions and prove "no structuring" against a curated subset. Closing it would need a tx-feed provider category (signed per-address chain history) that does not exist yet.

SettlementRegistry's `finalizeTrade` partially hardens the inherited gap (audit H-1). The PATTERN circuit exposes a `settlement_root` public input the registry recomputes from `(subTradeCount, recorded sub-settlement hashes)` and asserts equality; a single pattern proof is also marked `_usedPatternProofs` after consumption, so it cannot finalize a second trade. The binding is declarative — the circuit treats `settlement_root` as opaque — so a user with one curated transaction set can still generate N distinct pattern proofs for N different trades, but they cannot reuse one pattern proof across trades and they cannot finalize a trade with a pattern proof generated without knowledge of that trade's sub-settlement set. Cryptographic anchoring of the analyzed transactions to the on-chain sub-settlements would require a v2 compliance circuit that exposes transaction-amount commitments.

### Operational complexity as adoption tax

A production deployment at the recommended security level needs:

- Multisig owner behind `XochiTimelock`, signers in different geographies.
- Monitoring on every privileged event (`VerifierProposed`, `VersionRevocationProposed`, `ProviderPublisherSet`, `Paused`, `SignerPubkeyHashRegistered`, `SignerPubkeyHashRevoked`).
- Per-provider publisher EOA for credential roots, with rotation playbook.
- Per-provider signing daemon for the SIGNED variants, key in a KMS or HSM (the dev `HexKeyLoader` is unsafe), persistent replay-DB, tamper-evident audit log.
- Runbooks for key rotation, soundness-bug response, and the role boundaries (GUARDIAN / REGISTRAR / CONFIG).

This is the right shape for handling AML data. It is several orders of magnitude more operational rigor than "deploy a smart contract." Early integrators will run lighter (single-key owner, no monitoring, manual rotation) and accept the incident risk that goes with it.

### Long-lived attestations cross the post-quantum horizon

Attestations are stored permanently. The retroactive proof-of-innocence flow is the use case where this matters most. Someone querying `getHistoricalProof` in 2040 needs the verifier's `VK_HASH` to have been sound at submission time AND the underlying ECC to have held in the interim. The migration plan covers new attestations under a future PQ-secure verifier. It does not protect old ones from retroactive forgery once a CRQC exists.

Concretely: a CRQC in 2038 could mint backdated 2026-style proofs on a forked Oracle, or undermine the evidentiary value of 2026 attestations stored on the real one. Integrators who need durable retroactive evidence past the PQ migration should treat 2026 attestations as time-bounded and plan for re-attestation under a PQ scheme when one is standardized. This applies to every pre-quantum cryptographic attestation system. The proof-of-innocence story makes it sharper here.

### Cumulative trust surface

Each item above is a small dependency. Together they define the delivery envelope: a willing provider, an accepting regulator, a separate identity layer, a rigorous operator, intact cryptography. Drop any one and what's actually delivered is narrower than the headline.

The codebase is what it claims to be. The product around the codebase is a different question, and that question hasn't been answered yet.

---

## Out of scope

The following are explicitly out of scope for this codebase. Integrators / operators must address them at higher layers:

1. **Front-end UX security.** The contracts assume the user understands what they sign. Wallet plugins, transaction simulators, and chain explorers are external.
2. **Off-chain credential issuance integrity.** Providers are trusted to issue real credentials. Their off-chain processes (KYC vendor, document review) are external.
3. **Privacy of the submitter's identity.** Every attestation is linked on-chain to the submitter EOA in cleartext. Chain-analysis tools correlate submitter EOAs across attestations and against the rest of an address's on-chain activity, which limits the practical privacy benefit. What this system protects: the score, the signals, the credential attribute, the merkle path. What it does NOT protect: who is being scored. The practical privacy improvement over a Chainalysis-style API is "the regulator does not see your specific risk score," not "the regulator does not know who you are." ERC-5564 stealth addresses, mixers, and trusted relayers can obscure the submitter EOA but are out of scope here.
4. **Bridging attestations across chains.** Attestations are per-chain. Cross-chain attestation portability is an integrator concern.
5. **Sybil resistance.** Anyone can generate any proof for which they hold the witness. Per-user rate limiting is a higher-layer concern.
6. **Front-running of submissions.** The `submitter` binding to `msg.sender` prevents another party from claiming a user's proof, but does not prevent a copycat user from generating their _own_ proof for the same statement.

---

## Invariants enforced by tests

The following invariants are protected by regression tests; breaking them indicates a security regression:

| Invariant                                                                               | Test                                                                                                                           |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Cross-type proof confusion blocked at verifier layer                                    | `test_crossType_complianceProof_rejectedByRiskScoreVerifier`, `test_crossType_membershipProof_rejectedByNonMembershipVerifier` |
| STATICCALL prevents state mutation by malicious verifier                                | `test_staticcall_prevents_mutatingVerifier`                                                                                    |
| Public input length validated (count + 32-byte alignment)                               | `test_verifyProof_revert_wrongPublicInputCount`, fuzz tests in `LibraryFuzz.t.sol`                                             |
| Logical input count matches each verifier's `vk.publicInputsSize - PAIRING_POINTS_SIZE` | `test_invariant_logicalInputCount_matchesAllVerifiers`                                                                         |
| Frozen-Heart: tampering with public inputs invalidates proofs                           | `test_frozenHeart_*_publicInputMutation` (×6)                                                                                  |
| Frozen-Heart: tampering with proof bytes invalidates proofs                             | `test_frozenHeart_proofMutation_compliance`                                                                                    |
| `Ownable2Step` 48 h transfer deadline                                                   | `test_transferOwnership_revert_expired`                                                                                        |
| Per-type proof replay protection                                                        | existing `_usedProofs` tests                                                                                                   |
| Permanent config revocation                                                             | `test_updateProviderConfig_revert_reRegisterRevoked`                                                                           |
| Non-membership leaf adjacency                                                           | `test_main_revert_non_adjacent_brackets` (Noir)                                                                                |
| ATTESTATION cross-submitter forgery blocked                                             | `test_main_revert_wrong_submitter` (Noir)                                                                                      |
| Credential-root signature verified at publish time                                      | `test_publishCredentialRoot_compromisedPublisher_cannotForge`, `test_publishCredentialRoot_revert_wrongSigner`                  |
| EIP-712 digest parity between Solidity and TS                                           | `test_parity_credentialRootDigest` (Forge), `eip712-credential-root.test.ts` (vitest)                                          |
| RISK_SCORE trivial bounds rejected                                                      | `test_submitCompliance_revert_riskScore_*` family                                                                              |
| PATTERN analysis_type bound to STRUCTURING for SettlementRegistry                       | `test_finalizeTrade_revert_velocityAnalysisRejected`, `test_finalizeTrade_revert_publicInputsMismatch`                         |
| Credential root TTL window                                                              | `test_credentialRoot_expiresAfterTTL`, `test_credentialRoot_overlapWindow`                                                     |
| Pedersen parity between bb.js and Noir                                                  | `test_parity_with_sdk_signed_payload_hash`, `test_parity_with_sdk_signer_pubkey_hash` (Noir); `provider-pedersen.test.ts` (TS) |
| Strict jurisdictions reject unsigned screening proofs                                   | `test_strictJurisdiction_rejects_unsignedCompliance`, `test_strictJurisdiction_rejects_unsignedRiskScore`                      |
| Signer pubkey hash registry gates signed proofs                                         | `test_submitCompliance_signed_revert_unregisteredSignerPubkeyHash`, `test_submitCompliance_signed_revert_revokedSignerPubkeyHash` |

---

## Open items

These do not block deployment but should be tracked:

- Provider Issuance Protocol HTTP spec + reference SDK (UX work, separate stream).
- TS `CredentialClient` SDK for path resolution and root rotation handling.
- Per-provider revocation Merkle tree (currently revocation requires republishing the credentials tree without the bad leaf; a non-membership-based revocation tree would allow per-credential revocation without rebuilding).
- Toolchain version pinning enforced as a dedicated CI step (`make check-toolchain` is not currently a stand-alone CI gate; it runs transitively when `make fixtures` is invoked locally).
