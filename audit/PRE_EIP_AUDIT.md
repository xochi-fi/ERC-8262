# Pre-EIP X-Ray Audit -- erc-xochi-zkp

> ZK Compliance Oracle | ~2,592 in-scope nSLOC | `0c12337` (`main`) | Foundry + Nargo workspace | 2026-05-09

> **STATUS:** All 9 findings (F-1 through F-9) addressed on branch `fix/f-2-atomic-provider-expansion`. F-9 was acknowledged-only per its original recommendation; F-1 through F-8 each ship a code change with passing tests. See Section 4 per-finding for commit hashes.

Methodology: pashov-style x-ray applied manually. Section 1 is the protocol overview, Section 2 is the threat model, Section 3 is the invariant catalog, Section 4 is the pre-EIP findings list (the part that drives action), Section 5 is the verdict.

This document complements `docs/THREAT_MODEL.md` (which already covers the role-and-capability layer in depth). Findings here are issues this audit pass surfaced against the `main` ref above; the resolution column shows where each is fixed.

---

## 1. Protocol Overview

**What it does:** Records ZK-proof-backed compliance attestations on-chain so a regulator can verify a subject met a jurisdiction's AML threshold without seeing the underlying signals or trade.

- **Subjects (callers):** dApp users / settlement counterparties prove `meetsThreshold == true` for `(jurisdiction, providerSet, configHash, timestamp)`.
- **Providers:** screening signal sources whose weights are committed to in `providerSetHash` / `configHash`. Two trust modes:
  - Unsigned (`COMPLIANCE`, `RISK_SCORE`): integrator trusts off-chain provenance.
  - Signed (`COMPLIANCE_SIGNED`, `RISK_SCORE_SIGNED`): provider's secp256k1 signature is verified in-circuit; on-chain `signer_pubkey_hash` registry gates acceptance. Required for US BSA + Singapore.
- **Eight proof types**, each a separate Noir circuit + generated UltraHonk verifier. The Verifier contract routes by `proofType`; the Oracle owns input validation, replay protection, ratchet, and registry checks.
- **Settlement layer:** `SettlementRegistry` is immutable (no owner, no pause). Multi-leg trade finalization requires a `PATTERN` proof with `analysis_type == STRUCTURING`.
- **Admin model:** owner = `XochiTimelock` (24h HIGH / 6h LOW selector-based delay) + three operational roles split by responsibility (GUARDIAN = pause, REGISTRAR = registries, CONFIG = configs/upgrades).

### Contracts in Scope

| Subsystem           | Key Contracts                                                                                                                |      nSLOC | Role                                                                           |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ---------: | ------------------------------------------------------------------------------ |
| Verifier routing    | `XochiZKPVerifier`                                                                                                           |        383 | Maps proofType to UltraHonk verifier; timelocked upgrades; per-type pause      |
| Oracle              | `XochiZKPOracle`                                                                                                             |       1334 | Public-input validation, replay/ratchet, eight registries, attestation storage |
| Settlement          | `SettlementRegistry`                                                                                                         |        217 | Multi-leg trade finalization gated on PATTERN+STRUCTURING attestation          |
| Timelock            | `XochiTimelock`                                                                                                              |        195 | Selector-based two-tier admin delay                                            |
| Libraries           | `AccessControl`, `EIP712Attestation`, `EIP712CredentialRoot`, `JurisdictionConfig`, `Ownable2Step`, `Pausable`, `ProofTypes` |        463 | Roles, EIP-712 hashing, jurisdiction policy, proof-type schema                 |
| **Total in-scope**  |                                                                                                                              | **~2,592** |                                                                                |
| Generated verifiers | `src/generated/*_verifier.sol` (8x UltraHonk)                                                                                |     19,576 | Out of scope -- regenerated from circuits via bb                               |

### Core Flow

```
submitter (msg.sender)
  └─ generates proof off-chain (noir_js + bb.js)
      ├─ signed variants additionally request signature from provider daemon
      └─ proof bytes + bytes32-aligned publicInputs

XochiZKPOracle.submitCompliance / submitComplianceBatch
  ├─ whenNotPaused (global) + !_proofTypePaused[proofType]
  ├─ validateJurisdiction(jurisdictionId)
  ├─ _validateAndExtractTimestamp -- per-type input validation + signed-signals policy
  │     └─ requireSignedSignals(jurisdictionId) AND isUnsignedScreeningVariant(proofType) -> revert
  ├─ _ratchet(jurisdictionId, proofTimestamp) -- per-(subject,jurisdiction) non-decreasing
  ├─ _verifyAndRecordProof
  │     ├─ verifier.getVerifier(proofType) -> address
  │     ├─ ProofTypes.validatePublicInputs(proofType, publicInputs)
  │     ├─ IUltraVerifier(verifierUsed).verify(proof, inputs)  *static call*
  │     └─ proofHash = keccak256(proof, proofType, chainid, oracle); _usedProofs guard
  ├─ _buildAttestation -- subject = msg.sender, expiresAt = now + ttl
  └─ store: _attestations / _proofIndex / _proofTypes / _attestationHistory; emit ComplianceVerified

SettlementRegistry.registerTrade -> recordSubSettlement (per leg) -> finalizeTrade
  └─ finalizeTrade calls oracle.getProofType + oracle.getHistoricalProof
      └─ requires PATTERN, analysis_type == STRUCTURING, subject match, timestamp >= createdAt
```

---

## 2. Threat & Trust Model

### Protocol Classification

This protocol does not fit any of pashov's eight standard types (lending, AMM, vault, stablecoin, derivatives, LST, bridge, governance). It is a **ZK Compliance Oracle** -- a hybrid of:

- **Bridge characteristics:** off-chain authority (the provider) signs an attestation; on-chain validators (the registry + circuit) verify the signature. Adversary set inherits validator/relayer compromise + message replay concerns.
- **Governance characteristics:** owner-controlled registry surface protected by a timelock; role split (GUARDIAN/REGISTRAR/CONFIG) bounds blast radius. Governance attack vectors apply to role-grant flows.
- **Verifier-router characteristics:** new -- the trust kernel is the generated UltraHonk verifier. Soundness bugs in `bb` are existential.

### Adversary Ranking

1. **Soundness-bug exploiter against a deployed verifier** -- a bug in `bb`'s code generation, or in a circuit's constraint set, lets the attacker forge a passing proof with arbitrary public inputs. This is the highest-impact failure mode because no on-chain check downstream catches it. Mitigation: per-proof-type pause + version revocation (see Findings F-7).
2. **Compromised credential signing key** -- can mint forged `CredentialRootPublication`s for ATTESTATION proofs. Mitigated by separation from publisher EOA (audit C-1 closure) but still high-impact: see `revokeCredentialRoot` and `setCredentialSigner(provider, address(0))` for the rotation path.
3. **Compromised provider signing daemon (signed variants)** -- can sign arbitrary screening payloads, defeating the in-circuit signature check for `COMPLIANCE_SIGNED` / `RISK_SCORE_SIGNED`. Mitigated by `revokeSignerPubkeyHash` (instant via REGISTRAR) and by the registry being an additive set.
4. **Cross-deployment proof replayer** -- `proofHash` binds (proof, proofType, chainid, oracle), but the underlying ZK proof's public inputs do NOT include chainid/oracle. A second Oracle deployment that reuses the same signer registry would accept the same signed proof if `submitter == msg.sender` on the new Oracle. **In practice:** the submitter binding stops this for a different EOA, but a single attacker controlling both sides could replay against multiple Oracle instances (see F-6).
5. **Compromised owner / role holder** -- bounded by timelock + role split. GUARDIAN can pause and deny; REGISTRAR and CONFIG must wait HIGH/LOW. The single instant power that matters is `pauseProofType` (intentional), `denyProvider` (reversible), and `revokeVerifierVersion` (emergency only, documented).
6. **Initialization front-runner** -- `setVerifierInitial` is owner-only, no timelock, one-shot per proofType. If the post-deployment script is interrupted, the EOA owner remains in control until `transferOwnership` finishes its 2-step + 24h delay (see F-1).
7. **Subject-griefing replay** -- the timestamp ratchet + `_usedProofs` guard makes per-subject attestation extension expensive; griefing reduces to inflating `_attestationHistory[subject][jurisdictionId]` (no other user is affected; gas paid by attacker).

### Trust Boundaries

| Boundary                                  | Trust Model                                                 | Failure Damage                                                                                        |
| ----------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Off-chain proof generation -> Oracle      | Untrusted -- must verify against registered config + signer | Forged attestation if circuit unsound (F-7) or if registry contains wrong commitment (F-2)            |
| Provider publisher EOA -> Oracle          | Untrusted alone -- requires credential signer co-sig        | Forged credential roots only with both keys                                                           |
| Credential signer (HSM) -> publisher      | Trusted to sign honestly                                    | Forged ATTESTATION proofs against signed roots                                                        |
| Provider signing daemon (signed variants) | Trusted to sign honestly                                    | Forged COMPLIANCE_SIGNED / RISK_SCORE_SIGNED proofs                                                   |
| GUARDIAN role                             | Bounded -- can only pause + deny + immediate-revoke         | Cannot mint or extract; can DoS verification globally                                                 |
| CONFIG role                               | Bounded -- proposes only (timelock gates execution)         | Cannot bypass HIGH/LOW delays without compromising owner too                                          |
| Owner (= Timelock multisig in production) | Time-delayed bounded                                        | Subject to two-step ownership transfer; 24h HIGH delay on verifier upgrades                           |
| Generated `UltraHonk` verifier            | Cryptographically trusted                                   | A bb-generated verifier with a soundness bug is existential -- mitigations: pause + revoke + redeploy |

### Key Attack Surfaces

- **Initialization window for `setVerifierInitial`** -- `XochiZKPVerifier.sol:163-172`. Single shot per `(proofType)`, no timelock, owner-only. If the deploy script doesn't finish (verifier set + roles granted + ownership transferred), the deployer EOA can swap in a malicious verifier. Worth confirming the deploy runbook is atomic + checked. See F-1.
- **Provider denylist requires expansion registration** -- `XochiZKPOracle.sol:530-558`. `denyProvider` only applies to configs whose `_configProviders[configHash]` was registered via `registerProviderConfigExpansion`. A new config registered by `updateProviderConfig` _without_ a follow-up expansion call is **immune to denial**. Worth checking the operations runbook ensures expansion is always registered alongside config rotation. See F-2.
- **Signed-variants digest does not bind chain or contract** -- `circuits/shared/src/sig.nr` (Pedersen digest is `(provider_set_hash, signals, weights, timestamp, submitter)`); cross-deployment replay possible if attacker controls submitter address on both. Worth tracing whether any deployment scenario allows two Oracles to coexist with overlapping signer registries. See F-6.
- **`compactConfigHistory` is unbounded by current cap** -- `XochiZKPOracle.sol:486-517`. O(n) over `_configHistory` (cap = 256). Worst case ~2.5M gas; not a security issue but a usability constraint. Worth confirming this matches operational expectations.
- **`getAttestationHistory` returns unbounded array** -- `XochiZKPOracle.sol:351-357`. Documented; pagination alt exists. A subject can self-grief their own history view but cannot affect others. Surface acknowledged in NatSpec.
- **`MAX_BATCH_SIZE = 100`** for both verify and submit -- `XochiZKPVerifier.sol:61` and `XochiZKPOracle.sol:187`. UltraHonk verify is ~250-400k gas per call. 100 verifies = 25M-40M gas, very close to or above mainnet block gas. Worth confirming the batch cap matches realistic per-tx ceilings. See F-3.
- **`_recoverSigner` accepts legacy v=0/1 + does not enforce low-s** -- `XochiZKPOracle.sol:726-736`. Signature malleability would let two distinct signatures recover to the same signer; the `_credentialRoots[root].registeredAt != 0` guard makes the first publish absorb both (the second reverts). Replay before publish is bounded by `notBefore`/`notAfter`. Not exploitable today; worth either documenting or switching to OZ ECDSA which rejects high-s. See F-4.
- **Selector-based delay collision risk in Timelock** -- `XochiTimelock.sol:139-160`. `getDelay` defaults unknown selectors to HIGH (fail-safe). If a future LOW operation's name collides with a HIGH operation's selector (4-byte hash collision), the LOW path applies. Today's selectors don't collide; worth gating any future selector additions through a dedicated test.
- **`acceptOwnership(target)` in Timelock is proposer-callable on any address** -- `XochiTimelock.sol:189-192`. Proposer can call `acceptOwnership()` on an arbitrary contract. No privilege gained because only contracts that pre-emptively transferred to the timelock would accept it; harmless but worth documenting why this isn't gated.
- **Owner implicitly satisfies every role** -- `AccessControl.sol:43-45`. By design (single-key dev mode + production multisig path), but it means a compromised owner is equivalent to all three operational roles + role-grant power. The timelock is the only structural mitigation -- worth confirming the deployment runbook hands ownership to the Timelock immediately. See F-1.

---

## 3. Invariants

### Enforced Guards (selection)

| ID   | Predicate                                                                                                                  | Location                                                     | Purpose                                                                                  |
| ---- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| G-1  | `if (publicInputs.length % 32 != 0) revert UnalignedPublicInputs`                                                          | `ProofTypes.sol:52`                                          | Public inputs are bytes32-encoded field elements                                         |
| G-2  | `if (actual != expected) revert InvalidPublicInputLength`                                                                  | `ProofTypes.sol:55-57`                                       | Per-proofType input count must match circuit's `pub` arity                               |
| G-3  | `if (proofSubmitter != msg.sender) revert SubmitterMismatch`                                                               | `XochiZKPOracle.sol:1045/1093/1160/1195/1214/1233/1266/1308` | Binds the proof to the on-chain submitter                                                |
| G-4  | `if (_usedProofs[proofHash]) revert ProofAlreadyUsed`                                                                      | `XochiZKPOracle.sol:928`                                     | Per-(proof, proofType, chainid, oracle) replay protection                                |
| G-5  | `if (proofTimestamp < last) revert ProofTimestampNotMonotonic`                                                             | `XochiZKPOracle.sol:1001`                                    | Per-(subject, jurisdiction) timestamp ratchet                                            |
| G-6  | `if (diff > MAX_PROOF_AGE) revert ProofTimestampStale`                                                                     | `XochiZKPOracle.sol:1015-1017`                               | Bounds proof-internal timestamps to a 1-hour drift window                                |
| G-7  | `if (verifier.code.length == 0) revert NotAContract`                                                                       | `XochiZKPVerifier.sol:166/180`                               | Prevents EOA poisoning of the verifier mapping                                           |
| G-8  | `if (block.timestamp < readyAt) revert TimelockNotElapsed`                                                                 | `XochiZKPVerifier.sol:196/269`, `XochiTimelock.sol:91`       | Enforces the configured delay before execution                                           |
| G-9  | `if (msg.value != value) revert ValueMismatch`                                                                             | `XochiTimelock.sol:84`                                       | Prevents excess ETH being silently locked in the timelock                                |
| G-10 | `if (JurisdictionConfig.requireSignedSignals(j) && ProofTypes.isUnsignedScreeningVariant(p)) revert SignedSignalsRequired` | `XochiZKPOracle.sol:965-968`                                 | Per-jurisdiction signed-signals enforcement (US BSA / SG)                                |
| G-11 | `if (analysisType != PATTERN_STRUCTURING) revert PatternAnalysisTypeMismatch`                                              | `SettlementRegistry.sol:136-138`                             | Settlement finalization requires anti-structuring analysis (not VELOCITY / ROUND_AMOUNT) |

### Inferred Invariants (single-contract)

| ID   | Category                | On-chain | Property                                                                                                                                                   | Derivation                                                                                   |
| ---- | ----------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| I-1  | StateMachine            | Yes      | `_verifierHistory[proofType]` is append-only and 1-indexed; current = `history[length-1]`                                                                  | edge: setVerifierInitial / executeVerifierUpdate -> history.push                             |
| I-2  | StateMachine            | Yes      | `_revokedVersions[proofType][version] = true` is a one-shot latch (no path back)                                                                           | edge: `_doRevokeVersion`, no setter to `false`                                               |
| I-3  | StateMachine            | Yes      | `_revokedConfigs[configHash] = true` is a one-shot latch; once revoked, `updateProviderConfig` rejects re-registration                                     | edge: revokeConfig -> \_revokedConfigs[h] = true; guard at `XochiZKPOracle.sol:433`          |
| I-4  | StateMachine            | Yes      | `_credentialRoots[root].registeredAt != 0 -> publish reverts` (publish is one-shot per root)                                                               | edge: `XochiZKPOracle.sol:716`                                                               |
| I-5  | Bound                   | Yes      | `1 hours <= _attestationTTL <= 30 days` after every write                                                                                                  | guard-lift: `updateAttestationTTL` is the only writer, `XochiZKPOracle.sol:444`              |
| I-6  | Bound                   | Yes      | `_configHistory.length <= MAX_CONFIG_HISTORY` (256)                                                                                                        | guard-lift: writers `updateProviderConfig` (push, 434) and `compactConfigHistory` (pop only) |
| I-7  | Bound                   | Yes      | Settlement: `MIN_SUB_TRADES <= subTradeCount <= MAX_SUB_TRADES`                                                                                            | guard-lift: only writer is `registerTrade`, `SettlementRegistry.sol:50-52`                   |
| I-8  | Temporal                | Yes      | Settlement: `block.timestamp <= expiresAt` for non-finalized trades during `recordSubSettlement` / `finalizeTrade`                                         | temporal: `SettlementRegistry.sol:74,103,150`                                                |
| I-9  | Conservation (negative) | --       | No fund flows. Oracle, Verifier, Registry, and Timelock hold no protocol value (Timelock receives ETH only via `execute` value-pass-through and re-emits). | absence of Δ on any token/value variable                                                     |
| I-10 | Bound                   | Yes      | `_lastProofTimestamp[subject][jurisdictionId]` is non-decreasing per submission                                                                            | edge in `_ratchet`, `XochiZKPOracle.sol:999-1005`                                            |

### Inferred Invariants (cross-contract)

| ID  | On-chain | Property                                                                                                                       | Caller / Callee                                                                                                                                                                |
| --- | -------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| X-1 | Yes      | `SettlementRegistry.finalizeTrade` requires an attestation whose `subject == settlement.subject`                               | Caller: `SettlementRegistry.sol:124-127`; Callee writers: `XochiZKPOracle._proofIndex` set in `_submitSingle` / `submitCompliance`                                             |
| X-2 | Yes      | `SettlementRegistry.finalizeTrade` requires `oracle.getProofType(patternProofHash) == PATTERN`                                 | Caller: `SettlementRegistry.sol:121-122`; Callee: `_proofTypes` written in `_submitSingle` only                                                                                |
| X-3 | Yes      | `SettlementRegistry.finalizeTrade` requires `patternAttestation.timestamp >= settlement.createdAt` (anti-replay across trades) | Caller: `SettlementRegistry.sol:127`; Callee: attestation `timestamp` = `block.timestamp` at submission                                                                        |
| X-4 | **No**   | `_validSignerPubkeyHashes[h]` should imply `h` was generated by an honest provider's daemon                                    | The Oracle has no way to verify the off-chain provenance of the registered hash. Trust is REGISTRAR. Mitigation: instant `revokeSignerPubkeyHash`.                             |
| X-5 | **No**   | `_validConfigs[h]` should imply `_configProviders[h]` matches the off-chain provider expansion                                 | Oracle cannot recompute the Pedersen commitment over providers on-chain. Trust is CONFIG; `denyProvider` only enforces against expansions that were actually registered (F-2). |
| X-6 | Yes      | `_credentialRoots[root].providerId == providerId` for the provider claimed in the ATTESTATION proof                            | Caller: `_validateAttestationInputs:1188-1190`; Callee: written in `publishCredentialRoot:718-719` after EIP-712 signature check                                               |

### Economic / Higher-Order Invariants

| ID  | On-chain          | Property                                                                                                                                                                                                                | Derives From                                              |
| --- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| E-1 | Yes               | Every accepted attestation derives from a proof whose verifier `verify()` returned true at submission time, AND whose verifier address was the current `_verifiers[proofType]` at that block                            | I-1 + G-3 + G-4                                           |
| E-2 | Yes               | A trade can only be finalized when (a) every sub-leg has a verified attestation bound to the same subject + jurisdiction, AND (b) a PATTERN proof with `analysis_type == STRUCTURING` was generated _after_ `createdAt` | X-1 + X-2 + X-3 + G-11                                    |
| E-3 | **No** (residual) | Signed-variant attestations from US/SG submitters were generated by an Oracle-authorized signer                                                                                                                         | Reduces to X-4: the on-chain registry is trust-on-publish |

---

## 4. Findings (Pre-EIP)

### F-1 -- Initialization-window race in Verifier deploy (Medium-impact, one-time) ✓ RESOLVED `37b5fbf`

**Where:** `XochiZKPVerifier.setVerifierInitial` (`src/XochiZKPVerifier.sol:163-172`); `Ownable2Step.transferOwnership` flow.

**Issue:** `setVerifierInitial` is owner-only, no timelock, one-shot per proofType. The intended deploy flow is:

1. Deploy `XochiZKPVerifier(deployerEOA)`
2. Call `setVerifierInitial` 8 times for proof types 0x01-0x08
3. `transferOwnership(timelock)`
4. From the Timelock multisig, `acceptOwnership(verifier)`
5. Repeat (1)-(4) for `XochiZKPOracle`
6. Grant operational roles

If steps 2-4 are split across transactions, a compromised deployer EOA in the gap can call `setVerifierInitial` with a malicious verifier address that satisfies `code.length > 0` but always returns `true` from `verify()`. Recovery requires `proposeVerifier + executeVerifierUpdate` (24h).

**Recommendation:**

- Make the deploy script a single, atomic Foundry script that aborts on any sub-step failure and verifies post-conditions (each `_verifiers[i]` matches the expected generated address; ownership has been accepted by the timelock).
- Document the post-deploy invariant check in the runbook: `getVerifier(0x01..0x08)` returns the expected addresses AND `verifier.owner() == timelock`.
- Optionally: add an `initialize(address[8] verifiers)` constructor-time path so the eight verifier addresses are set at construction and the EOA gap doesn't exist.

### F-2 -- `denyProvider` is silently bypassable for configs without registered expansion (Medium) ✓ RESOLVED `6daacbd`

**Where:** `XochiZKPOracle.registerProviderConfigExpansion` (`src/XochiZKPOracle.sol:530-558`); `_configContainsDeniedProvider` (`src/XochiZKPOracle.sol:596-606`).

**Issue:** `denyProvider` only blocks proofs whose `configHash` has had its provider expansion registered. `updateProviderConfig` does _not_ atomically register the expansion -- they are two CONFIG-role calls. A new config that goes live before its expansion is registered:

- accepts COMPLIANCE / COMPLIANCE_SIGNED proofs (registry validates via `_validConfigs`)
- but `_configContainsDeniedProvider` returns `false` because `_configProviders[configHash]` is empty

If a CONFIG-role rotation script is interrupted between `updateProviderConfig` and `registerProviderConfigExpansion`, denylist enforcement is silently disabled for the new config until expansion is registered.

**Recommendation:**

- Atomic option: extend `updateProviderConfig` to take `uint256[] calldata providerIds` and write `_configProviders[newConfigHash]` in the same call. Reject if `length == 0`.
- Non-atomic option: add an Oracle-level invariant test asserting that for every `_validConfigs[h] == true` whose age exceeds N seconds (e.g. one timelock period), `_configProviders[h].length > 0`. Harder to enforce in-code; prefer the atomic option.
- Operational mitigation only (status quo): document that any CONFIG `updateProviderConfig` MUST be paired with `registerProviderConfigExpansion` in the same multisig batch.

### F-3 -- `MAX_BATCH_SIZE = 100` likely exceeds mainnet block gas (Low) ✓ RESOLVED `ea812c9`

**Where:** `XochiZKPVerifier.MAX_BATCH_SIZE`, `XochiZKPOracle.MAX_BATCH_SIZE` (both at constant declaration).

**Issue:** UltraHonk verify is ~250-400k gas per call (Solidity verifier; signed variants are higher because of the in-circuit ECDSA check). A 100-element batch:

- 100 verifies × 350k = 35M gas of cryptographic work, plus per-iteration validation + storage writes.
- Mainnet block gas limit ≈ 30M as of writing.

A 100-batch transaction is unlikely to fit in a single block on mainnet; on L2s with higher per-block gas (Arbitrum, Base) it may, but the gas snapshot in `.gas-snapshot` should clarify the actual ceiling.

**Recommendation:**

- Reduce `MAX_BATCH_SIZE` to a measured ceiling (10-20 likely fits comfortably; pin to whatever the gas snapshot shows is below 25M for the most expensive proof type).
- If the larger cap is intentional for L2-only deployments, document that 100-batch on mainnet WILL revert.
- Add a `GasBenchmark` test asserting `submitComplianceBatch(MAX_BATCH_SIZE)` fits under a configured gas budget.

### F-4 -- `_recoverSigner` does not enforce low-s + accepts legacy v=0/1 (Low / informational) ✓ RESOLVED `731f54b`

**Where:** `XochiZKPOracle._recoverSigner` (`src/XochiZKPOracle.sol:726-736`).

**Issue:** `ecrecover` accepts both `(r, s, v)` and `(r, n-s, v')` for the same digest, returning the same signer address. The `_credentialRoots[root].registeredAt != 0` guard at line 716 means only the first publish succeeds per root, so malleability cannot mint two roots. However:

- Pre-publish replay attempts (publisher submits twice with different `s` values) cost the publisher extra gas but achieve nothing.
- Future code paths that call `_recoverSigner` outside the one-shot publish guard would inherit malleability.
- The `if (v < 27) v += 27` legacy v normalization is acceptable but non-standard.

**Recommendation:** Switch to OpenZeppelin's `ECDSA.recover` (rejects `s > secp256k1n/2`, normalizes v). The library exists; the wrapper is ~20 lines saved.

### F-5 -- `acceptOwnership(target)` in Timelock is permissive (Informational) ✓ RESOLVED `ef5b1c2`

**Where:** `XochiTimelock.acceptOwnership` (`src/XochiTimelock.sol:189-192`).

**Issue:** Function lets `proposer` call `acceptOwnership()` on any address. No privilege is gained because only contracts that pre-emptively `transferOwnership(timelock)` would actually grant ownership; arbitrary calls are no-ops. Still, the function violates least-authority style.

**Recommendation:** Either remove (the proposer can `schedule + execute` the same call via the normal path, no convenience savings) or restrict by a target allowlist. Low priority.

### F-6 -- Signed-variant proofs do not bind chain or contract (Medium) ✓ RESOLVED `25d52ca` (+ xochi-sdk `080ceeb`)

**Where:** `circuits/shared/src/sig.nr`'s `compute_payload_hash` -- the Pedersen digest the provider signs is `(provider_set_hash, signals, weights, timestamp, submitter)`. No chainid or oracle address.

**Issue:** A signed proof generated for Oracle A on chain X is _cryptographically valid_ on Oracle B on chain Y if both have the same `signer_pubkey_hash` registered. The Oracle-level `proofHash = keccak256(proof, proofType, chainid, oracle)` plus the `submitter == msg.sender` check stop replay across deployments **for a different submitter EOA**. If the attacker controls the submitter EOA on both deployments (which is trivial -- it's their own EOA), they can re-use one signed payload to mint attestations on multiple Oracles.

This is **probably acceptable** for the v1 design because:

- The same submitter's attestation is independent on each Oracle (separate `_attestations` mapping).
- No fund flow makes the duplicate dangerous in itself.
- The off-chain audit trail of the provider sees one sign request, one attestation per chain.

But it does mean "one signature -> one attestation" is NOT a cross-chain invariant. The provider's replay-DB (Vouch/Dirk-style, per `docs/THREAT_MODEL.md`) sees one request and gracefully rejects duplicates -- but only if the daemon is a single instance. A horizontally-scaled signing daemon must share replay state.

**Recommendation:**

- Add `chain_id` and `oracle_address` to the in-circuit Pedersen digest. This requires a circuit revision and verifier regeneration. If accepted, add an EIP migration note.
- Failing that, document explicitly in the EIP that signed-variant attestations are NOT cross-chain unique: a single sign-request can produce N attestations across N deployments, and integrators must track per-(chainid, oracle) when reconciling.

### F-7 -- Verifier soundness incident response runbook should be tested (Operational) ✓ RESOLVED `45f0e8b`

**Where:** `XochiZKPVerifier.pauseProofType` + `revokeVerifierVersion` + `proposeVerifier` flow.

**Issue:** The threat model documents the response (pause, revoke, propose, execute over 24h). What is not in tests is the _integration runbook_: a unit test that walks the end-to-end "soundness bug discovered, mitigate, redeploy" sequence including:

1. Pause proof type -> existing verify calls revert
2. Revoke current version -> `verifyProofAtVersion(currentVersion)` reverts
3. Propose new verifier -> 24h elapses
4. Execute -> new verifier active; `verifyProofAtVersion(prevVersion)` still reverts (revoked)
5. Unpause -> new submissions resume

**Recommendation:** Add `test/Incident_VerifierSoundness.t.sol` that walks this path. A passing test is the runbook -- if it ever breaks, the response is broken.

### F-8 -- ProofTypes count expectations may drift from circuits (Low) ✓ RESOLVED `82d26c2`

**Where:** `ProofTypes.expectedPublicInputCount` (`src/libraries/ProofTypes.sol:28-46`); `circuits/*/src/main.nr` `pub` declarations.

**Issue:** The library hardcodes the public input count per proof type. If a circuit's `main()` adds or removes a `pub` field, the on-chain check silently rejects all proofs with `InvalidPublicInputLength` until the library is updated and redeployed. There is no automated check that the two are in sync.

**Recommendation:** Add a `make ci-circuits-sync` target (or a Foundry script) that:

1. Compiles each circuit (`nargo compile`)
2. Reads the `target/<circuit>.json` ABI to count `pub` fields
3. Asserts each count matches `ProofTypes.expectedPublicInputCount(p)` for the corresponding p

Wire into pre-EIP CI.

### F-9 -- `getAttestationHistory` unbounded (acknowledged, no action) ✓ DOCUMENTED

**Where:** `XochiZKPOracle.getAttestationHistory` (`src/XochiZKPOracle.sol:351-357`).

**Status:** Documented in NatSpec; pagination alt exists. Self-grief only. Listing here for completeness; **no action required** for EIP submission, but worth a one-line callout in the EIP that integrators MUST use the paginated variant.

---

## 5. X-Ray Verdict

**HARDENED** -- post-fix. Pre-EIP submission is not blocked. The original `ADEQUATE -> HARDENED` verdict was contingent on the punch list landing; with F-1 through F-8 closed and F-9 documented, every tier signal sits at HARDENED or above, and parity-check is now a CI gate.

**Tier signals (post-fix):**

- **Tests:** HARDENED -- unit (12 files) + stateless fuzz (29 functions) + Foundry invariant (5) + cross-validation tests + parity tests + soundness incident integration (`Incident_VerifierSoundness.t.sol`, F-7) + signature malleability rejection (F-4). 472 forge tests + 89 nargo tests pass on the post-fix branch. Adding 1-2 Halmos `check_` properties for the timestamp ratchet would push to FORTIFIED.
- **Docs:** HARDENED -- README, CLAUDE.md, full THREAT_MODEL.md (updated for F-2 atomicity and F-6 digest binding), EIP draft (signed-variant rows added with chain_id + oracle_address binding contract). NatSpec coverage is thorough.
- **Access Control:** HARDENED -- timelock + role split + 2-step ownership transfer + per-proof-type and global pause + permissive `acceptOwnership(target)` shortcut removed (F-5). The owner-implicit-role rule (`AccessControl.sol:43`) is the only remaining structural concern, mitigated by deploying ownership to the timelock — the hardened deploy script (F-1) now asserts that handoff in post-conditions.
- **Code hygiene:** No surfaced TODO/FIXME in security-critical paths.
- **Public-input parity (ZK-hybrid signal):** `make parity-check` is wired into CI (F-8) and gates every PR; current state is 8/8 circuits in parity (logical = physical = Solidity-expected; verifier `NUMBER_OF_PUBLIC_INPUTS` = physical + 16 for all UltraHonk-generated verifiers).

**Pre-EIP punch list:**

1. ✓ **F-1** `37b5fbf` -- deploy script hardened with post-condition assertions (oracle.verifier wiring, every proof-type verifier set + has code, initial provider expansion length matches, ownership shape matches `useTimelock`).
2. ✓ **F-2** `6daacbd` -- `updateProviderConfig(bytes32, string, uint256[])` writes the expansion atomically; constructor takes `initialProviderIds`. `registerProviderConfigExpansion` removed; every valid config has its expansion on-chain at registration.
3. ✓ **F-7** `45f0e8b` -- `Incident_VerifierSoundness.t.sol` walks pause -> propose -> 24h -> execute -> revoke v1 -> unpause end-to-end; `cannotRevokeCurrentVersion`, surgical-pause, and global-pause asserted alongside.
4. ✓ **F-3** `ea812c9` -- `MAX_BATCH_SIZE` lowered to 10 (24M gas at max, ~5M headroom under the 30M mainnet target); `test_gas_batch_atMaxSize_fitsBlockGasTarget` pins this to a 29M budget.
5. ✓ **F-6** `25d52ca` (+ xochi-sdk `080ceeb`) -- chain_id + oracle_address committed in the in-circuit Pedersen digest. Logical pub counts updated (compliance_signed 7 -> 9, risk_score_signed 9 -> 11). Verifier `NUMBER_OF_PUBLIC_INPUTS` regenerated (23 -> 25, 25 -> 27). Solidity validators assert against `block.chainid` and `address(this)`. Replay across chains/Oracles now requires forging a new ECDSA signature.
6. ✓ **F-8** `82d26c2` -- `parity-check.py` vendored from the `zk-x-ray` skill into `scripts/`, wired into Makefile + GitHub Actions.
7. ✓ **F-4** `731f54b` -- low-s enforcement on credential-root signatures via inlined `secp256k1n/2` constant; new `test_publishCredentialRoot_revert_highSMalleability`.
8. ✓ **F-5** `ef5b1c2` -- permissive `acceptOwnership(address)` removed from `XochiTimelock`; bootstrap workflow now uses standard schedule + execute.
9. ✓ **F-9** -- documented; integrators directed to `getAttestationHistoryPaginated`. No code change required (already documented in NatSpec).

**Structural facts:**

1. ~2,592 in-scope nSLOC across 4 contracts + 7 libraries; 8 generated UltraHonk verifiers excluded from review scope.
2. 8 proof types correspond 1:1 to 8 Noir circuits in `circuits/`; public-input arities are now CI-asserted to match between the on-chain library, the compiled circuits, and the generated verifiers (F-8 closure).
3. Admin surface is split across 4 roles (owner/GUARDIAN/REGISTRAR/CONFIG); owner is the meta-admin with implicit role membership.
4. Timelock has 2 delay tiers (24h HIGH / 6h LOW) selected by 4-byte selector hash classification. The selector for `updateProviderConfig` updated to `(bytes32,string,uint256[])` post-F-2.
5. 8 on-chain registries gate proof acceptance: `_validConfigs`, `_revokedConfigs`, `_validMerkleRoots`, `_validReportingThresholds`, `_credentialRoots`, `_validSignerPubkeyHashes`, `_providerPublisher`, `_credentialSigner`.

---

## Appendix: post-fix verification

| Gate                | Result                                                                                |
| ------------------- | ------------------------------------------------------------------------------------- |
| `forge test`        | 472 / 472 pass                                                                        |
| `make test-noir`    | 89 / 89 pass across 9 workspace packages                                              |
| `make parity-check` | 8 / 8 circuits in parity                                                              |
| `make fixtures`     | UltraHonk verifiers regenerated; `NUMBER_OF_PUBLIC_INPUTS` matches new logical counts |
| `forge fmt --check` | clean                                                                                 |
| Pre-commit hook     | passes                                                                                |

Branch: `fix/f-2-atomic-provider-expansion` (8 commits) + xochi-sdk `fix/f-6-bind-chain-oracle-in-digest` (1 commit, paired with F-6).
