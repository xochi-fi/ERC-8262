/// Provider-signed compliance proof circuit (audit finding I-1).
///
/// Identical semantics to the `compliance` circuit, but additionally verifies a
/// secp256k1 ECDSA signature over `(provider_set_hash, signals, weights, timestamp,
/// submitter)` produced by an Oracle-registered provider key. Closes the "honest
/// signals" gap: a user cannot submit `signals = [0; 8]` and prove "low risk"
/// without holding a provider's signature on those exact signals.
///
/// Public inputs (visible to verifier):
///   - jurisdiction_id: which jurisdiction's thresholds to use
///   - provider_set_hash: commitment to which providers were used
///   - config_hash: hash of the published weight configuration
///   - timestamp: block timestamp binding the proof
///   - meets_threshold: boolean result (1 = compliant, 0 = not)
///   - signer_pubkey_hash: Pedersen commitment to the provider's secp256k1 pubkey
///                        (Oracle validates against `_validSignerPubkeyHashes`)
///   - chain_id: EVM chain ID, committed in the in-circuit signed digest so a
///               provider signature cannot be replayed cross-chain (audit F-6)
///   - oracle_address: deployment address of the consuming Oracle, committed in
///                     the in-circuit signed digest so a signature cannot be
///                     replayed against a different Oracle on the same chain
///                     (audit F-6)
///   - submitter: address of the authorized proof submitter (anti-frontrun)
///
/// Private inputs (known only to prover):
///   - signals, weights, weight_sum, provider_ids, num_providers (as in `compliance`)
///   - signature: 64-byte secp256k1 ECDSA signature (r || s)
///   - pubkey_x, pubkey_y: 32-byte big-endian secp256k1 pubkey coordinates

use erc8262_shared::{
    compute_risk_score,
    get_high_threshold,
    compute_provider_set_hash,
    verify_weight_sum,
    compute_config_hash,
    validate_timestamp,
    validate_provider_slots,
    compute_signed_payload_hash,
    verify_provider_signed_signals,
    DOMAIN_SIGNED_SIGNALS,
};

fn main(
    // --- Private inputs ---
    signals: [u32; 8],
    weights: [u32; 8],
    weight_sum: u32,
    provider_ids: [Field; 8],
    num_providers: u32,
    signature: [u8; 64],
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],

    // --- Public inputs ---
    jurisdiction_id: pub u8,
    provider_set_hash: pub Field,
    config_hash: pub Field,
    timestamp: pub Field,
    meets_threshold: pub bool,
    signer_pubkey_hash: pub Field,
    // Audit F-6: bind the signed digest to a specific deployment.
    chain_id: pub Field,
    oracle_address: pub Field,
    submitter: pub Field,
) {
    // 1. Validate weight_sum is positive
    assert(weight_sum > 0, "Weight sum must be positive");

    // 2. Validate provider count + slot invariants (identical to unsigned variant)
    validate_provider_slots(signals, weights, provider_ids, num_providers);

    // 3. Verify weight_sum matches active weights
    verify_weight_sum(weights, weight_sum);

    // 4. Compute the risk score
    let score = compute_risk_score(signals, weights, weight_sum);

    // 5. Get the jurisdiction threshold
    let threshold = get_high_threshold(jurisdiction_id);

    // 6. Verify the meets_threshold claim
    let computed_meets = score < threshold;
    assert(computed_meets == meets_threshold, "Threshold result mismatch");

    // 7. Verify provider set hash matches the committed set
    let computed_provider_hash = compute_provider_set_hash(provider_ids, weights);
    assert(computed_provider_hash == provider_set_hash, "Provider set hash mismatch");

    // 8. Verify config hash commits to the weight configuration
    let computed_config_hash = compute_config_hash(weights);
    assert(computed_config_hash == config_hash, "Config hash mismatch");

    // 9. Timestamp must be within reasonable bounds
    validate_timestamp(timestamp);

    // 10. Anchor submitter as a public input (oracle enforces submitter == msg.sender).
    assert(submitter != 0, "submitter must be non-zero");

    // 11. *** Provider signature verification (audit I-1 remediation). ***
    // The provider signs a Pedersen digest committing to the exact signals + weights
    // + provider_set_hash + timestamp + submitter the prover discloses privately.
    // Without this, signal honesty is not enforced cryptographically. The Oracle's
    // _validSignerPubkeyHashes registry authenticates `signer_pubkey_hash`.
    let payload_hash = compute_signed_payload_hash(
        DOMAIN_SIGNED_SIGNALS,
        chain_id,
        oracle_address,
        provider_set_hash,
        signals,
        weights,
        timestamp,
        submitter,
    );
    verify_provider_signed_signals(
        pubkey_x,
        pubkey_y,
        signature,
        payload_hash,
        signer_pubkey_hash,
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// The failure-mode tests below need no valid signature. The signed-bundle tests at
// the end use signatures precomputed off-chain (xochi-sdk signSignals) over the
// in-circuit Pedersen digest.

#[test(should_fail_with = "signer_pubkey_hash mismatch")]
fn test_main_revert_wrong_pubkey_hash() {
    let signals = [20, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let provider_ids: [Field; 8] = [1, 0, 0, 0, 0, 0, 0, 0];

    let provider_set_hash = compute_provider_set_hash(provider_ids, weights);
    let config_hash = compute_config_hash(weights);

    let zero_sig: [u8; 64] = [0; 64];
    let zero_x: [u8; 32] = [0; 32];
    let zero_y: [u8; 32] = [0; 32];

    main(
        signals, weights, 100, provider_ids, 1,
        zero_sig, zero_x, zero_y,
        0, // EU
        provider_set_hash,
        config_hash,
        1700000000,
        true,
        0xdeadbeef, // mismatched pubkey hash -> assertion fires before signature check
        1,          // chain_id
        0xabcd1234, // oracle_address
        0xdead,
    );
}

#[test(should_fail_with = "Threshold result mismatch")]
fn test_main_revert_wrong_meets_threshold() {
    let signals = [80, 0, 0, 0, 0, 0, 0, 0]; // 8000 bps, above EU threshold (7100)
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let provider_ids: [Field; 8] = [1, 0, 0, 0, 0, 0, 0, 0];

    let provider_set_hash = compute_provider_set_hash(provider_ids, weights);
    let config_hash = compute_config_hash(weights);

    let zero_sig: [u8; 64] = [0; 64];
    let zero_x: [u8; 32] = [0; 32];
    let zero_y: [u8; 32] = [0; 32];

    main(
        signals, weights, 100, provider_ids, 1,
        zero_sig, zero_x, zero_y,
        0, // EU
        provider_set_hash,
        config_hash,
        1700000000,
        true, // claim meets threshold but score 8000 >= 7100 -> fails BEFORE signature check
        0,
        1,          // chain_id
        0xabcd1234, // oracle_address
        0xdead,
    );
}

#[test(should_fail_with = "Inactive signal must be zero")]
fn test_main_revert_inactive_signal_nonzero() {
    let signals = [60, 50, 0, 0, 0, 0, 0, 0]; // signal[1] nonzero but only 1 provider
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let provider_ids: [Field; 8] = [1, 0, 0, 0, 0, 0, 0, 0];

    let provider_set_hash = compute_provider_set_hash(provider_ids, weights);
    let config_hash = compute_config_hash(weights);

    let zero_sig: [u8; 64] = [0; 64];
    let zero_x: [u8; 32] = [0; 32];
    let zero_y: [u8; 32] = [0; 32];

    main(
        signals, weights, 100, provider_ids, 1,
        zero_sig, zero_x, zero_y,
        0,
        provider_set_hash,
        config_hash,
        1700000000,
        true,
        0,
        1,          // chain_id
        0xabcd1234, // oracle_address
        0xdead,
    );
}

// ---------------------------------------------------------------------------
// Signed-bundle tests (review #5). The bundle and both signatures are the ones
// in risk_score_signed/src/main.nr (same key, same signals, signed once under the
// 0x07 domain and once under the 0x08 domain); see that file for provenance.
// ---------------------------------------------------------------------------

global FIXTURE_SIGNER_PUBKEY_HASH: Field =
    0x294fc7a4edbc711b1c3ceceb89474957aea2974dbf3d27efe759a1ecef35d6dc;
global FIXTURE_PUBKEY_X: [u8; 32] = [
    32, 200, 84, 126, 134, 190, 235, 89, 194, 183, 197, 14, 72, 83, 155, 145, 70, 127, 150, 181,
    178, 60, 72, 184, 9, 78, 30, 217, 164, 212, 226, 66,
];
global FIXTURE_PUBKEY_Y: [u8; 32] = [
    45, 74, 60, 178, 139, 138, 55, 189, 66, 187, 156, 255, 146, 98, 182, 228, 212, 219, 184, 140,
    139, 128, 126, 35, 147, 85, 247, 92, 95, 166, 66, 144,
];
/// Signature over the bundle's 0x07 (COMPLIANCE_SIGNED) digest.
global FIXTURE_SIG_COMPLIANCE_SIGNED: [u8; 64] = [
    138, 191, 70, 221, 230, 120, 2, 250, 16, 119, 25, 190, 110, 156, 167, 62, 113, 176, 118, 43,
    122, 51, 197, 253, 239, 146, 7, 22, 71, 34, 104, 83, 3, 205, 251, 124, 84, 47, 205, 235, 247,
    215, 233, 248, 116, 233, 138, 165, 178, 75, 162, 192, 132, 92, 141, 148, 127, 185, 82, 141, 99,
    202, 106, 170,
];
/// Signature over the bundle's 0x08 (RISK_SCORE_SIGNED) digest.
global FIXTURE_SIG_RISK_SIGNED: [u8; 64] = [
    182, 115, 199, 138, 49, 136, 65, 189, 35, 71, 72, 208, 193, 89, 65, 185, 16, 157, 119, 27, 54,
    175, 210, 53, 18, 123, 253, 65, 234, 199, 103, 2, 112, 233, 231, 138, 229, 193, 168, 120, 241,
    198, 7, 173, 114, 19, 157, 40, 160, 61, 75, 20, 243, 126, 101, 201, 54, 138, 59, 255, 192, 4,
    184, 81,
];

/// Prove EU compliance for the fixture bundle (score 2500 < 7100) with `signature`.
fn prove_fixture_bundle(signature: [u8; 64]) {
    let signals = [25, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let provider_ids: [Field; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
    main(
        signals, weights, 100, provider_ids, 1,
        signature, FIXTURE_PUBKEY_X, FIXTURE_PUBKEY_Y,
        0, // EU
        compute_provider_set_hash(provider_ids, weights),
        compute_config_hash(weights),
        1700000000,
        true,
        FIXTURE_SIGNER_PUBKEY_HASH,
        31337,                                      // chain_id
        0x2e234dae75c793f67a35089c9d99245e1c58470b, // oracle_address
        0xdead,
    );
}

#[test]
fn test_main_accepts_compliance_signed_bundle() {
    prove_fixture_bundle(FIXTURE_SIG_COMPLIANCE_SIGNED);
}

#[test(should_fail_with = "invalid provider signature on signals")]
fn test_main_rejects_risk_signed_bundle() {
    // Same key and bundle, signed for RISK_SCORE_SIGNED (0x08): not a 0x07 signature.
    prove_fixture_bundle(FIXTURE_SIG_RISK_SIGNED);
}
