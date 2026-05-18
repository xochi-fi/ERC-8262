# TODO

## Current Status

- 499/499 Solidity tests pass (Verifier, Oracle, Registry, Timelock, Integration, Gas, Invariant, EIP712, ThresholdCrossValidation, AccessControl, ProviderDenylist, LibraryFuzz, AttestationRatchet, Incident_VerifierSoundness, signed-variant oracle paths, verifier codehash pinning, Oracle state-machine invariants, COMPLIANCE_MULTI_SIGNED)
- 105/105 Noir tests pass (10 workspace packages incl. compliance_signed, risk_score_signed, compliance_multi_signed, shared sig + multi_sig parity vectors with chain_id + oracle_address binding)
- xochi-sdk: signed-variant API extended with `chainId` + `oracleAddress` (paired with circuit revision; SDK side on `fix/f-6-bind-chain-oracle-in-digest`)
- EIP draft aligned with implementation (signed-variant rows include the F-6 chain/oracle binding contract)
- Tooling: nargo 1.0.0-beta.20, forge 1.5.1, bb 4.0.0-nightly.20260120
- CI green; Slither: 0 findings on hand-written code; `make parity-check` is now a CI gate (F-8) -- 9/9 circuits in parity
- Gas: ~2.43M verify, ~2.85M submit; `MAX_BATCH_SIZE = 10` (audit F-3, ~24M at cap, fits 30M mainnet block)
- Pre-EIP audit: see [`audit/PRE_EIP_AUDIT.md`](audit/PRE_EIP_AUDIT.md). All 9 findings closed on `fix/f-2-atomic-provider-expansion`.
- Client SDK: `../xochi-sdk` (also published as `@xochi/sdk@^0.2.0`)

## Completed

<details>
<summary>M-of-N multi-provider compliance proof (2026-05-14)</summary>

New proof type `COMPLIANCE_MULTI_SIGNED = 0x09` reduces the single-provider trust assumption to M-of-N. A single proof bundles up to `MAX_PROVIDERS_MULTI = 5` parallel signer slots; each active slot independently verifies a secp256k1 ECDSA signature and asserts its risk score is below the jurisdiction floor. Forging an attestation now requires compromising M of N independent signing keys, not just one.

- New shared Noir module `circuits/shared/src/multi_sig.nr` (`DOMAIN_MULTI_SIGNED_SIGNALS`, `compute_slot_payload_hash`, `verify_slot_or_skip` gated wrapper, `assert_distinct_signers`, `count_active_signers`).
- New circuit `circuits/compliance_multi_signed/` with 14 logical public inputs: jurisdiction_id, provider_set_hash, config_hash, timestamp, meets_threshold, threshold_m, 5 × signer_pubkey_hash, chain_id, oracle_address, submitter. Each signature commits to a slot-specific Pedersen digest (distinct domain tag + `slot_index`) so a 0x07 signature cannot satisfy a 0x09 slot and the same signature cannot be replayed across slots.
- Solidity: `ProofTypes.COMPLIANCE_MULTI_SIGNED` constant + 14-input arity, `JurisdictionConfig.minMultiProviderThreshold(US=2, SG=2, EU=1, UK=1)`, new Oracle validator `_validateComplianceMultiSignedInputs` (signer-registry authorization, on-chain distinctness, threshold enforcement, jurisdiction floor, F-6 chain/oracle binding, denylist, ratchet). New errors: `InsufficientSigners`, `BelowJurisdictionMinProviders`, `DuplicateSigner`, `InvalidThresholdM`.
- Deploy script registers the new verifier; CI parity gate reports 9/9 in parity (compliance_multi_signed: 14/14/14/30).
- Tests: 12 new Foundry tests covering happy 2-of-3 / 3-of-5, insufficient-signer revert, signer revocation mid-flight, duplicate-signer revert, threshold_m bounds, US/SG jurisdiction-floor enforcement, F-6 chain/oracle mismatches, submitter mismatch. Plus 6 inline Noir tests for structural failure modes.

Off-chain orchestration (M coordinated signing daemons producing per-slot signatures) is out of scope for this in-repo work; tracked separately on `xochi-sdk` once this circuit lands. A future `_large` variant for N > 5 will be added if institutional demand emerges (see plan note); slot 0x0a is reserved.

</details>

<details>
<summary>Oracle state-machine invariants (2026-05-14)</summary>

Foundry invariants now exercise the Oracle's state machine with a working handler (previously every submission reverted on `MAX_PROOF_AGE` because the fixed `proofTimestamp=1700000` was outside the 1h window; existing invariants were vacuously true). Handler now submits with `block.timestamp`, restricts jurisdictions to EU/UK (unsigned-compliance eligible), and exercises config + merkle root admin paths.

Three new invariants (256 runs × 500 calls each):

- **`invariant_ratchetMatchesMaxSubmitted`**: for every `(handler, jurisdiction)` pair the handler ever submitted under, `oracle.lastProofTimestamp(handler, jId)` equals the max successful `proofTimestamp`. Catches any code path that lets an older proof overwrite a newer attestation.
- **`invariant_revokedConfigsStayRevoked`**: every config in the handler's revoked-list returns `isValidConfig(c) == false`. Verifies the permanent-revocation contract.
- **`invariant_merkleRootStateMachine`**: handler-tracked merkle roots are valid iff they were registered and not subsequently revoked.

All 256 × 500 = 128k call sequences pass with 0 reverts across 8 invariants. Total Solidity: 486 tests passing.

</details>

<details>
<summary>Verifier codehash pinning (2026-05-14)</summary>

`proposeVerifier(uint8, address, bytes32)` now pins the expected EXTCODEHASH at proposal time, re-checked at execute time. Belt-and-suspenders on the existing 24h timelock: a CONFIG-role compromise that swaps bytecode at the proposed address (CREATE2 redeploy + same-tx SELFDESTRUCT factory, alt-EVM chains pre-EIP-6780, or simple "wrong contract pasted at execute" social engineering) is now caught.

- `VerifierProposal` gains `expectedCodehash`; new `CodehashMismatch(address, bytes32 expected, bytes32 actual)` error fires at both propose and execute.
- `VerifierProposed` event extended with `expectedCodehash`. `getPendingVerifier` now returns `(address, uint256, bytes32)`.
- `Timelock.getDelay` unchanged: the new selector falls through to the `HIGH_DELAY` default (24h), same as before.
- Regression: `test_proposeVerifier_revert_codehashMismatch_atPropose`, `test_executeVerifierUpdate_revert_codehashChangedMidWindow` (uses `vm.etch` to simulate mid-window bytecode swap), `test_proposeAndExecute_succeeds_whenCodehashMatches`.

Breaking change for any off-chain caller of `proposeVerifier`. SDK + deploy script side: none today; the SDK and `script/*.s.sol` do not call `proposeVerifier`.

</details>

<details>
<summary>Pre-EIP audit fix-first sweep (2026-05-09)</summary>

`audit/PRE_EIP_AUDIT.md` surfaced 9 findings against `0c12337`. All 9 closed on branch `fix/f-2-atomic-provider-expansion` (8 commits) plus xochi-sdk `fix/f-6-bind-chain-oracle-in-digest` (1 commit, paired with F-6). 472 forge tests + 89 nargo tests + parity-check pass post-fix.

- **F-2 `6daacbd`** -- atomicize `updateProviderConfig` with provider expansion. Constructor takes `initialProviderIds`; new signature is `updateProviderConfig(bytes32, string, uint256[])`; `registerProviderConfigExpansion` removed. Every valid config now has its expansion on-chain at registration, closing the silent denylist-bypass window.
- **F-7 `45f0e8b`** -- `Incident_VerifierSoundness.t.sol` runbook-as-code. Walks the documented incident response (pause -> propose -> 24h -> execute -> revoke -> unpause) end-to-end so any future regression in the response sequence breaks CI instead of breaking the runbook during a live incident.
- **F-3 `ea812c9`** -- `MAX_BATCH_SIZE` lowered from 100 to 10. Per-proof gas baseline (~2.4M verify / ~2.83M submit) put 100 batched at 240M-283M gas, 10x over mainnet's 30M block target. New gas-bounded test pins the cap to a 29M budget.
- **F-4 `731f54b`** -- enforce low-s on credential-root signatures. Inlined `secp256k1n / 2` constant rejects malleable (`r, n-s`) tuples without adding OZ as a dependency.
- **F-5 `ef5b1c2`** -- removed permissive `acceptOwnership(address)` shortcut from `Timelock`. Bootstrap workflow now uses standard schedule + execute; every action goes through the configured delay.
- **F-8 `82d26c2`** -- vendor `parity-check.py` from the `zk-x-ray` skill into `scripts/`; wire `make parity-check` into the Noir Circuits CI job. Logical / physical / Solidity-expected / verifier `NUMBER_OF_PUBLIC_INPUTS` are now CI-asserted to agree on every PR.
- **F-1 `37b5fbf`** -- harden `script/Deploy.s.sol` with post-condition assertions (oracle.verifier wiring, every proof-type verifier set + has code, initial provider expansion length matches, ownership shape matches `useTimelock`). A multi-step partial deploy now reverts the broadcast.
- **F-6 `25d52ca` + xochi-sdk `080ceeb`** -- bind `chain_id` + `oracle_address` into the in-circuit Pedersen digest for signed variants. compliance_signed logical pubs 7 -> 9, risk_score_signed 9 -> 11. Verifier `NUMBER_OF_PUBLIC_INPUTS` regenerated to 25 / 27. A single provider signature can no longer mint attestations across chains or alternate Oracle deployments. xochi-sdk parity vector regenerated to `0x161ce9164a86defd6b8c44e9923690407bea0488eb15bd91b99ce71438dae106`.
- **F-9** -- documented (no code change). `getAttestationHistory` is unbounded by design; integrators should use `getAttestationHistoryPaginated`.

Methodology side-effect: drafted the `zk-x-ray` skill (https://github.com/DROOdotFOO/agent-skills/pull/1) -- a pashov-inspired pre-audit briefing generator for ZK + EVM hybrid protocols. The parity-check gate above is one of its outputs.

</details>

<details>
<summary>Credential-root signature verification (2026-04-29)</summary>

Two-key separation for ATTESTATION credential roots. The publisher EOA submits the publish tx; a separate per-provider signing key (held in HSM/KMS) signs an EIP-712 `CredentialRootPublication` struct, and the Oracle verifies the signature via `ecrecover` before storing the root. A compromised publisher EOA can no longer mint forged credentials.

- New library `EIP712CredentialRoot.sol` with the `CredentialRootPublication { providerId, root, cidHash, notBefore, notAfter }` type hash. Reuses the `ERC8262Oracle / 1` EIP-712 domain.
- Oracle additions: `_credentialSigner[providerId]` mapping, `setCredentialSigner` / `getCredentialSigner` (REGISTRAR), modified `publishCredentialRoot(providerId, root, cid, notBefore, notAfter, signature)` with `ecrecover` verification, new errors and events.
- Off-chain: `xochi-sdk/src/provider/eip712.ts` (TS digest, parity-tested byte-for-byte against Solidity), `credential-root-signer.ts` (`signCredentialRoot` returning `{signature, digest, signer}`), daemon route `POST /sign-credential-root`.
- ATTESTATION circuit and `attestation_verifier.sol` unchanged. No VK_HASH change. Existing UltraHonk fixture proofs verify byte-for-byte.
- Regression: `test_publishCredentialRoot_compromisedPublisher_cannotForge`, `test_setCredentialSigner_rotation_oldSigRejected`, plus EIP-712 parity (`test_parity_credentialRootDigest`).
</details>

<details>
<summary>Provider-signed signals (2026-04-28)</summary>

Two new proof types (`COMPLIANCE_SIGNED = 0x07`, `RISK_SCORE_SIGNED = 0x08`) verify a secp256k1 ECDSA signature in-circuit over a Pedersen digest of `(provider_set_hash, signals, weights, timestamp, submitter)`. Per-jurisdiction policy via `JurisdictionConfig.requireSignedSignals`: US BSA and Singapore reject the unsigned variants; EU AMLD6 and UK MLR accept either.

- New circuits: `compliance_signed`, `risk_score_signed`. Shared `sig.nr` module with `compute_signed_payload_hash`, `compute_signer_pubkey_hash`, `verify_provider_signed_signals`. New domain tags `DOMAIN_SIGNED_SIGNALS`, `DOMAIN_SIGNER_PUBKEY`.
- Oracle additions: `_validSignerPubkeyHashes` registry, `registerSignerPubkeyHash` / `revokeSignerPubkeyHash` (REGISTRAR), `_validateComplianceSignedInputs`, `_validateRiskScoreSignedInputs`, `SignedSignalsRequired` revert in dispatcher.
- Off-chain primitives in xochi-sdk: `src/provider/` (Pedersen mirror parity-tested against Noir, secp256k1 keystore, signer with low-S ECDSA, replay-protection DB), `proveComplianceSigned()` and `proveRiskScoreSigned()` on `XochiProver`.
- Reference signing daemon at `xochi-sdk/daemon/`: HTTP + bearer/mTLS, `/sign`, `/pubkey-hash`, `/healthz`, audit log, replay refusal. Patterned on Vouch/Dirk's slashing-protection-DB approach.
- Trust-model docs (README, EIP draft, `THREAT_MODEL.md`) updated. Post-quantum migration path documented.
</details>

<details>
<summary>Foundational hardening (2026-04-08 through 2026-04-28)</summary>

- Circuit hardening: non-membership u64 range checks, risk-score overflow guard, provider-set assertions, pattern floor overflow, Pedersen properties documented.
- Oracle/Verifier hardening: `view`-correct verify path, public-input validation per type, TOCTOU fix, `(proof, proofType)` proof-hash keying, 32-byte alignment, merkle/threshold registries, permanent config revocation, replay protection, paginated history, `Ownable2Step` 48h transfer.
- Pre-mainnet (2026-04-22): submitter front-run binding, `MAX_PROOF_AGE = 1h`, verifier replacement timelock, `MIN_TIME_WINDOW`, cross-type semantic gap closed via `proofType` in attestation struct + `checkComplianceByType`, code existence check, per-proof-type pause, emergency `revokeVerifierVersion`, Noir u1 → bool migration.
- Static analysis (2026-04-25): Slither v0.11.5 (0 findings on hand-written code), Mythril (0 issues), `compactConfigHistory()`, EIP-712 typed-data lib, `decodePublicInputs` calldatacopy optimization, paired Noir/Solidity threshold cross-validation, edge-case tests at u64 max and 1-bps boundaries.
- Defense-in-depth (2026-04-28): cross-chain replay binding (`keccak256(proof, proofType, chainId, address(this))` + `computeProofHash()`), `AccessControl` library splitting GUARDIAN/REGISTRAR/CONFIG roles, per-provider denylist (`registerProviderConfigExpansion` + `denyProvider`).
- Per-subject attestation ratchet (2026-04-28): `_lastProofTimestamp[subject][jurisdictionId]` + `_ratchet()` enforces non-decreasing proof-internal timestamps. Prevents older-proof-overwriting-newer attacks.
- Code refactor (2026-04-08): shared Noir helpers + `Ownable2Step` / `Pausable` abstractions deduped ~110 lines.
- Infrastructure: `generate-fixtures.sh` (incl. verifier-only mode for circuits without `Prover.toml`), `Makefile`, pre-commit `forge fmt`, e2e harness, TS consumer SDK + on-chain integration tests, CI jobs, gas-snapshot regression.
</details>

## Medium-priority hardening

- [ ] **Jurisdiction threshold timelock**: route `JurisdictionConfig` updates through `Timelock LOW_DELAY` (6h). Today the thresholds and `requireSignedSignals` flag are compile-time constants; relevant only if/when these become governed.

## Lower-priority hardening

- [ ] FROST-secp256k1 threshold signing for the provider daemon (V2). Requires Schnorr-secp256k1 verifier in the circuit (not in Noir 1.0-beta stdlib); ~5-8 days of focused work plus a coordinator/participant gRPC protocol.
- [ ] Mythril in CI alongside Slither.
- [ ] Persistent replay DB for the signing daemon (sqlite/redis); the in-memory default is fine for short-lived processes only.
- [ ] KMS / HSM `KeyLoader` implementations; the daemon ships with HEX-only loaders for dev.
- [ ] Exhaustive cross-type proof routing rejection (all permutations across 8 proof types).

## Next up

### 1. Testnet deployment (Sepolia + Base Sepolia)

Prerequisite: CI green.

- [ ] Deploy script updates: chain-specific config (RPC URLs, gas settings)
- [ ] Deploy generated verifiers (8 contracts per chain incl. signed variants)
- [ ] Deploy ERC8262Verifier, register all 8 per-type verifiers
- [ ] Deploy ERC8262Oracle with initial config hash
- [ ] Deploy Timelock with Safe multi-sig as proposer
- [ ] Transfer Verifier + Oracle ownership to timelock
- [ ] Register initial merkle roots, reporting thresholds, signer pubkey hashes
- [ ] Verify all contracts on Etherscan/Basescan
- [ ] Smoke test: submit a real compliance proof on testnet (both unsigned and signed variants)
- [ ] Document deployed addresses in README

### 2. Documentation site

- [ ] EIP spec as primary reference
- [ ] Integration guide (SDK usage, proof generation, signing daemon, on-chain verification)
- [ ] Circuit architecture diagrams (incl. signed-variant flow)
- [ ] Deployment guide (testnet + mainnet)
- [ ] Threat model + security considerations

## Pre-deployment (blocked on testnet validation)

- [ ] External security audit (Solidity + Noir circuits) -- internal pre-EIP audit complete; see `audit/PRE_EIP_AUDIT.md`
- [ ] EIP submission to ethereum/EIPs
- [ ] Provider signal mock server for local development (the reference signing daemon is the closest thing today)
- [x] Formal verification of jurisdiction threshold logic

## Gas benchmarks

| Operation              | Gas    | Notes                                    |
| ---------------------- | ------ | ---------------------------------------- |
| verifyProof (any type) | ~2.43M | UltraHonk verification dominates         |
| submitCompliance       | ~2.85M | +380K Oracle overhead (storage + events) |
| batch verify x1        | 2.86M  | Baseline                                 |
| batch verify x2        | 4.84M  | ~2.42M/proof                             |
| batch verify x5        | 12.07M | ~2.41M/proof                             |
| batch verify x10       | 24.12M | ~2.41M/proof (linear)                    |

Signed-variant verifiers add ~30% to the verify cost from in-circuit ECDSA.

## Design decisions (documented, not bugs)

- **meetsThreshold always true**: failed proofs revert at the verifier, so only compliant proofs are stored. The field is kept for `checkCompliance()` ergonomics.
- **No access control on submitCompliance()**: anyone can prove their own compliance. Restricting to relayers would centralize.
- **Proof hash keyed on (proof, proofType, chainId, address(this))**: prevents cross-type collision and cross-chain / cross-deployment replay.
- **Jurisdiction thresholds and signed-signals flags hardcoded**: by design per ERC spec. Updating means a contract upgrade, which is the right friction for regulatory parameters.
- **Pedersen vs Poseidon2**: Noir API stability dictates Pedersen for now. Homomorphic properties are not exploitable in current circuit compositions. Migrate when Poseidon2 stabilizes.
- **TTL boundary inclusive**: `checkCompliance` uses `<=` for `expiresAt`; attestation valid for exactly TTL seconds.
- **verifier immutable on Oracle**: the router address is immutable; per-type verifiers behind it are upgradable via `proposeVerifier` + `executeVerifierUpdate`.
- **Circuit names match ProofTypes**: directories (pattern, attestation, compliance_signed, etc.) match Solidity constants 1:1.
- **compliance vs risk_score (vs \*\_signed)**: both unsigned circuits use `compute_risk_score()` from shared. Compliance is the primary jurisdiction-aware proof; risk_score is a raw scoring primitive (GT/LT/range, no jurisdiction). Signed variants add an in-circuit secp256k1 verify; same authority anchor (`signer_pubkey_hash` registered on the Oracle) regardless of whether jurisdiction policy requires them.
- **Double timelock for verifier updates**: external `Timelock` (24h) + internal verifier timelock (24h) = 48h total. Defense-in-depth. Emergency bypass via `revokeVerifierVersion` and `pauseProofType` (no timelock).
- **Per-jurisdiction signed-signals (US/SG strict, EU/UK permissive)**: stricter regimes require provider-signed signals; permissive regimes keep the cheaper unsigned path. Permissive jurisdictions accept signed proofs voluntarily; the policy sets a floor, not a cap.
