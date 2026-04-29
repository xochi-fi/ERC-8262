# TODO

## Current Status

- 450/450 Solidity tests pass (Verifier, Oracle, Registry, Timelock, Integration, Gas, Invariant, EIP712, ThresholdCrossValidation, AccessControl, ProviderDenylist, LibraryFuzz, AttestationRatchet, signed-variant oracle paths)
- 87/87 Noir tests pass (9 workspace packages incl. compliance_signed, risk_score_signed, shared sig parity vectors)
- 204/204 xochi-sdk tests pass (incl. provider signing daemon + on-chain E2E for COMPLIANCE_SIGNED)
- EIP draft aligned with implementation (signed variants documented)
- Tooling: nargo 1.0.0-beta.20, forge 1.5.1, bb 4.0.0-nightly.20260120
- CI green; Slither: 0 findings on hand-written code
- Gas: ~2.43M verify, ~2.85M submit, linear batch scaling (signed variants ~30% heavier per circuit)
- Client SDK: `../xochi-sdk` (also published as `@xochi/sdk@^0.2.0`)

## Completed

<details>
<summary>Credential-root signature verification (2026-04-29)</summary>

Two-key separation for ATTESTATION credential roots. The publisher EOA submits the publish tx; a separate per-provider signing key (held in HSM/KMS) signs an EIP-712 `CredentialRootPublication` struct, and the Oracle verifies the signature via `ecrecover` before storing the root. A compromised publisher EOA can no longer mint forged credentials.

- New library `EIP712CredentialRoot.sol` with the `CredentialRootPublication { providerId, root, cidHash, notBefore, notAfter }` type hash. Reuses the `XochiZKPOracle / 1` EIP-712 domain.
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
- Infrastructure: `generate-fixtures.sh` (incl. verifier-only mode for circuits without `Prover.toml`), `Makefile`, pre-commit `forge fmt`, xochi e2e harness, TS consumer SDK + on-chain integration tests, CI jobs, gas-snapshot regression.
</details>

## Medium-priority hardening

- [ ] **Verifier codehash pinning**: `proposeVerifier(uint8 proofType, address newVerifier, bytes32 expectedCodehash)` rejects when `address(newVerifier).codehash != expectedCodehash`. Belt-and-suspenders on top of the 24h timelock; blocks SELFDESTRUCT-and-redeploy bait-and-switch by a compromised owner.
- [ ] **Jurisdiction threshold timelock**: route `JurisdictionConfig` updates through `XochiTimelock LOW_DELAY` (6h). Today the thresholds and `requireSignedSignals` flag are compile-time constants; relevant only if/when these become governed.

## Lower-priority hardening

- [ ] FROST-secp256k1 threshold signing for the provider daemon (V2). Requires Schnorr-secp256k1 verifier in the circuit (not in Noir 1.0-beta stdlib); ~5-8 days of focused work plus a coordinator/participant gRPC protocol.
- [ ] Mythril in CI alongside Slither.
- [ ] Foundry invariant tests for Oracle state machine (attestation monotonicity, no orphaned roots, denied-provider configs always reject).
- [ ] Persistent replay DB for the signing daemon (sqlite/redis); the in-memory default is fine for short-lived processes only.
- [ ] KMS / HSM `KeyLoader` implementations; the daemon ships with HEX-only loaders for dev.
- [ ] Exhaustive cross-type proof routing rejection (all permutations across 8 proof types).

## Next up

### 1. Testnet deployment (Sepolia + Base Sepolia)

Prerequisite: CI green.

- [ ] Deploy script updates: chain-specific config (RPC URLs, gas settings)
- [ ] Deploy generated verifiers (8 contracts per chain incl. signed variants)
- [ ] Deploy XochiZKPVerifier, register all 8 per-type verifiers
- [ ] Deploy XochiZKPOracle with initial config hash
- [ ] Deploy XochiTimelock with Safe multi-sig as proposer
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

- [ ] External security audit (Solidity + Noir circuits)
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
- **compliance vs risk_score (vs *_signed)**: both unsigned circuits use `compute_risk_score()` from shared. Compliance is the primary jurisdiction-aware proof; risk_score is a raw scoring primitive (GT/LT/range, no jurisdiction). Signed variants add an in-circuit secp256k1 verify; same authority anchor (`signer_pubkey_hash` registered on the Oracle) regardless of whether jurisdiction policy requires them.
- **Double timelock for verifier updates**: external `XochiTimelock` (24h) + internal verifier timelock (24h) = 48h total. Defense-in-depth. Emergency bypass via `revokeVerifierVersion` and `pauseProofType` (no timelock).
- **Per-jurisdiction signed-signals (US/SG strict, EU/UK permissive)**: stricter regimes require provider-signed signals; permissive regimes keep the cheaper unsigned path. Permissive jurisdictions accept signed proofs voluntarily; the policy sets a floor, not a cap.
