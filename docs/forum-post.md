This draft proposes an ERC for ZK compliance attestations: users prove jurisdiction-specific compliance at the moment of the transaction, cryptographically. No identity revealed, no TEE, no trusted third party. A regulator who wants to check the work checks a proof; they never see the trade.

The short version:

ZK proof of jurisdiction-specific compliance. The attestation is stored onchain with a TTL, retrievable later for proof-of-innocence.

Nine proof types. Six unsigned (compliance, risk score, pattern, attestation, membership, non-membership) and three signed variants that add an in-circuit provider signature, including an M-of-N up to five signers.

Three trust tiers, explicit: user-attested, provider-signed, credential-attested. Strict jurisdictions reject the first.

Four jurisdictions wired with published thresholds: EU AMLD6, US BSA, UK MLR, Singapore.

Adjacent work that doesn’t fit the same problem: ERC-3643 (identity-revealing), Privacy Pools (set membership only), EIP-7963 (single-token gate), ERC-1922 (stagnant 2019 verifier interface), ERC-7812 (general statement registry — this could plug in as a compliance registrar). Full treatment in the draft’s Related Work.

Two interfaces. The verifier routes by proof type and keeps a version history, so a proof valid a year ago is still checkable after the verifier has been upgraded. That matters: if you can’t re-verify a proof later, you can’t do proof-of-innocence after a discovered circuit bug.

interface IXochiZKPVerifier {
function verifyProof(uint8 proofType, bytes calldata proof, bytes calldata publicInputs) external view returns (bool);
function verifyProofBatch(uint8[] calldata, bytes[] calldata, bytes[] calldata) external view returns (bool);
function verifyProofAtVersion(uint8 proofType, uint256 version, bytes calldata proof, bytes calldata publicInputs) external view returns (bool);
// ... + getVerifier / getVerifierAtVersion / getVerifierVersion
}

The oracle handles submission, stores the attestation with a TTL, and validates public inputs against eight onchain registries (config hashes, merkle roots, reporting thresholds, per-provider credential roots, signer pubkey hashes, etc.). It records the verifier used at submission, so a mid-transaction verifier upgrade can’t cause the attestation to disagree with itself later.

The nine proof types:

ID

Name

Logical public inputs

0x01

Compliance

6

0x02

Risk Score

8

0x03

Pattern

7

0x04

Attestation

6

0x05

Membership

5

0x06

Non-membership

5

0x07

Compliance Signed

9

0x08

Risk Score Signed

11

0x09

Compliance Multi-Signed

14 (M-of-N up to 5)

Public input semantics, jurisdiction thresholds, and full validation rules are in the draft.

Six open questions where we want feedback:

Should the unsigned tier exist in the standard? Compliance (0x01) and Risk Score (0x02) take screening signals as a private witness with no signature — the circuit proves the score was computed correctly, not that the inputs are honest. Strict jurisdictions reject this tier; permissive ones accept either. Our current thoughts are to keep them, since they compose with downstream honest-signal checks and save gas on permissive paths. But we can see the ‘cut-them’ argument.

Hardcoded jurisdictions vs. a registry. Four are hardcoded, thresholds in-spec. Small, auditable, cheap. Cost: a fifth jurisdiction is an ERC revision rather than a runtime change. Worth the rigidity?

Nine proof types — too many? The in-circuit ECDSA verify changes the constraint set, so folding signed variants into an oracle-side flag would charge every unsigned path for something it isn’t using. But nine may read as surface-area bloat. Tell us.

Pattern proof’s analysis_type field: 1=anti-structuring, 2=velocity, 3=round-amounts. Registry or fixed set? Registry is more general but complicates consumers that bind to a specific analysis.

EIP-7702 and AA composition. submitter == msg.sender plays cleanly with 7702-delegated EOAs and 4337 batchers. We’d like AA folks to sanity-check paymasters and ERC-1271 contract signers as compliance subjects.

Cross-chain replay on unsigned variants. Unsigned types don’t bind chain_id in-circuit. The onchain proofHash is chain-scoped, so storage replay is blocked, but the raw proof bytes can mint a fresh attestation on a different chain or a forked Oracle. Signed variants close this in-circuit. Should the standard require in-circuit chain binding for all proof types, or is the onchain guard enough for the unsigned tier?

Reference implementation at . Foundry 0.8.28 Cancun, nine Noir circuits pinned to nargo 1.0.0-beta.20, UltraHonk verifiers from bb 4.0.0-nightly.20260120. All nine verifiers fit under EIP-170 after we rewrote the pairing() free function as inline Yul (~186 bytes and ~800 gas per call). Proof fixtures for the six unsigned types; signed variants exercised from TypeScript SDK tests with fresh ECDSA witnesses per run. Audit-prep complete.

ERCs PR linking in once opened. Authors: @DROOdotFOO, @bloo-berries, @Jabher.
