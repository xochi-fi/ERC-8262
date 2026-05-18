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
// Happy-path tests with valid signatures require an external signer (ethers / alloy)
// to produce ECDSA signatures over the in-circuit Pedersen digest. Those are exercised
// via Foundry integration tests against generated fixtures rather than nargo tests.
// Nargo tests below cover the structural logic and the failure modes that do not
// require a valid signature.

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
