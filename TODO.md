# TODO

## Current Status

- 424/424 Solidity tests pass (Verifier, Oracle, Registry, Timelock, Integration, Gas, Invariant, EIP712, ThresholdCrossValidation, AccessControl, ProviderDenylist, LibraryFuzz)
- 77/77 Noir circuit tests pass (7 workspace packages)
- 28/35 TS consumer SDK tests pass (7 todo)
- 7/7 client SDK tests pass
- EIP draft aligned with implementation
- Tooling: nargo 1.0.0-beta.20, forge 1.5.1, bb 4.0.0-nightly.20260120
- CI green (solidity + circuits + sdk jobs); Slither: 0 findings
- Gas: ~2.43M verify, ~2.85M submit, linear batch scaling
- Client SDK: `../xochi-sdk` (also published as `@xochi/sdk@^0.1.1`)

## Completed

<details>
<summary>Foundational security (circuits + Solidity)</summary>

Circuit hardening: non-membership u64 range checks, risk-score overflow guard (MAX_WEIGHT, weight_sum validation), provider-set array assertions, pattern floor overflow guard, Pedersen homomorphic properties documented.

Oracle/Verifier hardening: IUltraVerifier `view` correctness, public-input validation for all 6 proof types, TOCTOU elimination, proof-hash keying on `(proof, proofType)`, 32-byte alignment check, merkle-root + reporting-threshold registries, config revocation with `CannotRevokeCurrentConfig` guard, `_usedProofs` replay protection, paginated attestation history, Ownable2Step 48h transfer timeout.
</details>

<details>
<summary>Pre-mainnet hardening (2026-04-22)</summary>

- Proof front-running: `submitter: pub Field` in all 6 circuits, Oracle enforces `submitter == msg.sender`
- Timestamp staleness: `MAX_PROOF_AGE = 1h` for COMPLIANCE/ATTESTATION/MEMBERSHIP/NON_MEMBERSHIP
- Verifier replacement timelock: `proposeVerifier`/`executeVerifierUpdate` (24h), `setVerifierInitial` deploy-only
- Pattern time_window floor: `MIN_TIME_WINDOW = 3600s`
- Cross-type semantic gap: `proofType` in ComplianceAttestation struct + `checkComplianceByType()`
- Code existence check: `NotAContract` rejects EOA verifier addresses
- Per-proof-type pause + emergency `revokeVerifierVersion`
- Noir u1 -> bool migration (nargo 1.0.0-beta.20)
</details>

<details>
<summary>Static analysis + tests (2026-04-25)</summary>

- Slither v0.11.5 -- 36 findings triaged (all false positives / by-design); `slither.config.json` + CI job; generated UltraHonk verifiers excluded (separately audited by Aztec)
- Mythril -- 0 issues on Oracle, Verifier, SettlementRegistry, Timelock
- `compactConfigHistory()` to free slots after revocations
- EIP-712 typed-data lib (`EIP712Attestation`) for off-chain attestation verification, fork-safe `DOMAIN_SEPARATOR()`
- `ProofTypes.decodePublicInputs` calldatacopy optimization (~60 gas/input saved)
- Paired Noir + Solidity threshold cross-validation tests
- Circuit edge-case tests: u64 max boundary, 1-bps-below-threshold, MAX_REPORTING_THRESHOLD
</details>

<details>
<summary>Defense-in-depth hardening (2026-04-28)</summary>

- Cross-chain replay binding: `proofHash = keccak256(proof, proofType, chainId, address(this))`. Same proof bytes can no longer be replayed across chains or alternate Oracle deployments. New `computeProofHash()` view as the source-of-truth helper for integrators.
- Role-based access control (`AccessControl` library): GUARDIAN (pause/incident), REGISTRAR (merkle/threshold/publisher curation), CONFIG (provider config, TTL, verifier upgrades). Owner implicitly holds every role; only owner can grant/revoke. Splits the admin surface so a single key compromise no longer unlocks the full attack surface.
- Per-provider denylist: `registerProviderConfigExpansion(configHash, providerIds[])` (CONFIG, append-only) + `denyProvider(id)` / `undenyProvider(id)` (GUARDIAN). Surgical revocation of a single compromised KYC provider without rotating the whole config; opt-in via expansion registration so configs without an expansion are unaffected.
- 37 new tests across `AccessControl.t.sol` + `ProviderDenylist.t.sol`; Slither: 0 findings.
</details>

<details>
<summary>Infrastructure + integrations</summary>

- `generate-fixtures.sh`, Makefile (build/test/lint/benchmark), pre-commit `forge fmt` check
- xochi e2e harness, runtime proof generation, TS consumer SDK, `@xochi/sdk` published to npm
- CI: solidity + circuits + sdk jobs, slither job, gas-snapshot regression check
- XochiTimelock: 24h verifier / 6h config tiers, proposer + guardian roles
</details>

<details>
<summary>Code quality refactor (2026-04-08)</summary>

- Extracted Noir shared utilities (`verify_weight_sum`, `weights_to_fields`, `compute_config_hash`, `validate_timestamp`, `compute_tx_set_hash`); circuit deduplication ~60 lines
- Solidity `Ownable2Step` + `Pausable` abstracts; ~50 lines deduplication
- Expanded NatSpec on Merkle bit encoding, two-round hashing rationale, truncation-attack explanation
</details>

## Medium-priority hardening (next)

- [x] **Per-subject attestation ratchet** (2026-04-28): `_lastProofTimestamp[subject][jurisdictionId]` enforces non-decreasing proof-internal timestamps via the new `_ratchet()` helper. Each `_validate*Inputs` returns its proof timestamp (proof-internal for COMPLIANCE/ATTESTATION/MEMBERSHIP/NON_MEMBERSHIP, `block.timestamp` for RISK_SCORE/PATTERN). Equal timestamps allowed so legitimate same-block submissions of different proof types can coexist. Public getter `lastProofTimestamp(subject, jurisdictionId)`. 8 new tests in `AttestationRatchet.t.sol`.
- [ ] **Verifier codehash pinning**: `proposeVerifier(uint8 proofType, address newVerifier, bytes32 expectedCodehash)` rejects when `address(newVerifier).codehash != expectedCodehash`. Belt-and-suspenders on top of the 24h timelock -- forces a compromised owner who pushes a swap to also know the codehash committed to at proposal time, blocking SELFDESTRUCT-and-redeploy bait-and-switch.
- [ ] **Jurisdiction threshold timelock**: route `JurisdictionConfig` updates through `XochiTimelock LOW_DELAY` (6h). Today the thresholds are compile-time constants -- this only becomes relevant if/when they become governed.

## Lower-priority hardening

- [ ] Mythril in CI alongside Slither (currently only Slither is automated)
- [ ] Foundry invariant tests for Oracle state machine (attestation monotonicity, no orphaned roots, denied-provider configs always reject)
- [ ] SDK `.todo()` tests for pattern + attestation circuits (blocked on circuit builds in CI)
- [ ] Exhaustive cross-type proof routing rejection (all 30 mismatch permutations)

## Next up

### 1. Testnet deployment (Sepolia + Base Sepolia)

Prerequisite: CI green.

- [ ] Deploy script updates: chain-specific config (RPC URLs, gas settings)
- [ ] Deploy generated verifiers (6 contracts per chain)
- [ ] Deploy XochiZKPVerifier, register all 6 per-type verifiers
- [ ] Deploy XochiZKPOracle with initial config hash
- [ ] Deploy XochiTimelock with Safe multi-sig as proposer
- [ ] Transfer Verifier + Oracle ownership to timelock
- [ ] Register initial merkle roots + reporting thresholds
- [ ] Verify all contracts on Etherscan/Basescan
- [ ] Smoke test: submit a real compliance proof on testnet
- [ ] Document deployed addresses in README

### 2. Documentation site

- [ ] EIP spec as primary reference
- [ ] Integration guide (SDK usage, proof generation, on-chain verification)
- [ ] Circuit architecture diagrams
- [ ] Deployment guide (testnet + mainnet)
- [ ] Threat model + security considerations

## Pre-deployment (blocked on testnet validation)

- [ ] External security audit (Solidity + Noir circuits)
- [ ] EIP submission to ethereum/EIPs
- [ ] Provider signal mock server for local development
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

## Design decisions (documented, not bugs)

- **meetsThreshold always true**: Failed proofs revert at verifier, so only compliant proofs are recorded. Field kept for checkCompliance() query interface.
- **No access control on submitCompliance()**: Anyone can prove compliance for themselves. Restricting to relayers would add centralization.
- **Proof hash keyed on (proof, proofType)**: Different proof types produce different hashes even for identical proof bytes. Prevents cross-type collision.
- **Jurisdiction thresholds hardcoded**: By design per ERC spec. Updating requires contract upgrade, appropriate for regulatory thresholds.
- **Pedersen vs Poseidon2**: Using Pedersen due to Noir API stability. Homomorphic properties not exploitable in current circuit compositions. Migrate when Poseidon2 stabilizes.
- **TTL boundary inclusive**: checkCompliance uses `<=` for expiresAt. Attestation valid for exactly TTL seconds inclusive.
- **verifier immutable on Oracle**: XochiZKPVerifier address is immutable. Individual per-type verifiers are upgradeable via setVerifier().
- **Circuit names match ProofTypes**: Circuit directories (pattern, attestation) match Solidity ProofTypes constants 1:1. Previously `anti_structuring` and `tier_verification`, renamed for ontology alignment.
- **compliance vs risk_score**: Both use `compute_risk_score()` from shared. Compliance is the primary jurisdiction-aware proof. Risk score is a raw scoring primitive for custom integrations (GT/LT/range, no jurisdiction). Intentional composition, not duplication.
- **Double timelock for verifier updates**: External XochiTimelock (24h) + internal verifier timelock (24h) = 48h total. Defense-in-depth: even if the timelock controller is compromised, the verifier's internal timelock provides a second layer. Emergency bypass via `revokeVerifierVersion` and `pauseProofType` (no timelock).
