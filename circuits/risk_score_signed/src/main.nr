/// Provider-signed risk-score circuit (audit finding I-1).
///
/// Identical semantics to `risk_score`, but additionally verifies a secp256k1
/// ECDSA signature over `(provider_set_hash, signals, weights, timestamp, submitter)`
/// produced by an Oracle-registered provider key. Closes the "honest signals" gap
/// for the standalone risk-score primitive used in custom integrations.
///
/// Public inputs:
///   - proof_type: 0x01 (threshold) or 0x02 (range)
///   - direction: for threshold, 1=GT, 2=LT
///   - bound_lower, bound_upper: bounds (basis points)
///   - result: boolean
///   - config_hash: hash of published weight configuration
///   - provider_set_hash: commitment to which providers were used
///   - signer_pubkey_hash: Pedersen commitment to the provider signer pubkey
///   - chain_id: EVM chain ID, committed in the signed digest (audit F-6)
///   - oracle_address: deployment address of the consuming Oracle (audit F-6)
///   - submitter: address of the authorized proof submitter
///
/// Private inputs:
///   - signals, weights, weight_sum, provider_ids, num_providers (as in `risk_score`)
///   - signature: 64-byte secp256k1 ECDSA signature (r || s)
///   - pubkey_x, pubkey_y: 32-byte big-endian secp256k1 pubkey coordinates

use xochi_shared::{
    MAX_PROVIDERS,
    compute_risk_score,
    verify_weight_sum,
    compute_config_hash,
    compute_provider_set_hash,
    compute_signed_payload_hash,
    verify_provider_signed_signals,
};

global PROOF_THRESHOLD: u8 = 0x01;
global PROOF_RANGE: u8 = 0x02;
global DIRECTION_GT: u8 = 1;
global DIRECTION_LT: u8 = 2;

fn main(
    // --- Private ---
    signals: [u32; 8],
    weights: [u32; 8],
    weight_sum: u32,
    provider_ids: [Field; 8],
    num_providers: u32,
    signature: [u8; 64],
    pubkey_x: [u8; 32],
    pubkey_y: [u8; 32],
    // The signed payload includes the timestamp; risk_score has no public timestamp,
    // so we treat it as a private witness bound into the signature.
    signed_timestamp: Field,

    // --- Public ---
    proof_type: pub u8,
    direction: pub u8,
    bound_lower: pub u32,
    bound_upper: pub u32,
    result: pub bool,
    config_hash: pub Field,
    provider_set_hash: pub Field,
    signer_pubkey_hash: pub Field,
    // Audit F-6: bind the signed digest to a specific deployment.
    chain_id: pub Field,
    oracle_address: pub Field,
    submitter: pub Field,
) {
    // 1. Validate inputs
    assert(num_providers >= 1, "At least one provider required");
    assert(num_providers <= MAX_PROVIDERS, "Too many providers");
    assert(weight_sum > 0, "Weight sum must be positive");
    assert(
        (proof_type == PROOF_THRESHOLD) | (proof_type == PROOF_RANGE),
        "Invalid proof type",
    );

    // 2. Validate signals and provider slots
    for i in 0..8 {
        if (i as u32) < num_providers {
            assert(signals[i] <= 100, "Signal out of range");
            assert(weights[i] > 0, "Active provider weight must be positive");
            assert(provider_ids[i] != 0, "Active provider ID must be non-zero");
        } else {
            assert(signals[i] == 0, "Inactive signal must be zero");
            assert(weights[i] == 0, "Inactive weight must be zero");
            assert(provider_ids[i] == 0, "Inactive provider ID must be zero");
        }
    }

    verify_weight_sum(weights, weight_sum);

    // 3. Compute the risk score
    let score = compute_risk_score(signals, weights, weight_sum);

    // 4. Verify the claimed result
    if proof_type == PROOF_THRESHOLD {
        if direction == DIRECTION_GT {
            assert(result == (score > bound_lower), "Threshold GT mismatch");
        } else if direction == DIRECTION_LT {
            assert(result == (score < bound_lower), "Threshold LT mismatch");
        } else {
            assert(false, "Invalid direction");
        }
    } else {
        assert(bound_upper >= bound_lower, "Invalid range");
        let in_range = (score >= bound_lower) & (score <= bound_upper);
        assert(result == in_range, "Range mismatch");
    }

    // 5. Verify config hash
    let computed_config = compute_config_hash(weights);
    assert(computed_config == config_hash, "Config hash mismatch");

    // 6. Verify provider set hash
    let computed_provider_hash = compute_provider_set_hash(provider_ids, weights);
    assert(computed_provider_hash == provider_set_hash, "Provider set hash mismatch");

    // 7. Anchor submitter
    assert(submitter != 0, "submitter must be non-zero");

    // 8. *** Provider signature verification (audit I-1 remediation). ***
    let payload_hash = compute_signed_payload_hash(
        chain_id,
        oracle_address,
        provider_set_hash,
        signals,
        weights,
        signed_timestamp,
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
// Tests (failure-mode only; happy paths exercised via Foundry fixtures)
// ---------------------------------------------------------------------------

#[test(should_fail_with = "signer_pubkey_hash mismatch")]
fn test_main_revert_wrong_pubkey_hash() {
    let signals = [60, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let provider_ids: [Field; 8] = [1, 0, 0, 0, 0, 0, 0, 0];

    let config = compute_config_hash(weights);
    let provider_hash = compute_provider_set_hash(provider_ids, weights);

    let zero_sig: [u8; 64] = [0; 64];
    let zero_x: [u8; 32] = [0; 32];
    let zero_y: [u8; 32] = [0; 32];

    main(
        signals, weights, 100, provider_ids, 1,
        zero_sig, zero_x, zero_y, 1700000000,
        PROOF_THRESHOLD, DIRECTION_GT, 5000, 0, true,
        config, provider_hash,
        0xdeadbeef,
        1,          // chain_id
        0xabcd1234, // oracle_address
        0xdead,
    );
}

#[test(should_fail_with = "Threshold GT mismatch")]
fn test_main_revert_threshold_mismatch() {
    let signals = [20, 0, 0, 0, 0, 0, 0, 0]; // score = 2000
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let provider_ids: [Field; 8] = [1, 0, 0, 0, 0, 0, 0, 0];

    let config = compute_config_hash(weights);
    let provider_hash = compute_provider_set_hash(provider_ids, weights);

    let zero_sig: [u8; 64] = [0; 64];
    let zero_x: [u8; 32] = [0; 32];
    let zero_y: [u8; 32] = [0; 32];

    main(
        signals, weights, 100, provider_ids, 1,
        zero_sig, zero_x, zero_y, 1700000000,
        PROOF_THRESHOLD, DIRECTION_GT, 5000, 0, true, // 2000 > 5000 false; claim true
        config, provider_hash,
        0,
        1,          // chain_id
        0xabcd1234, // oracle_address
        0xdead,
    );
}
