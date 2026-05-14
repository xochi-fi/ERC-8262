/// Multi-provider signed compliance proof (proof type 0x09).
///
/// Verifies that M out of N independent screening providers (each registered with
/// the Oracle's `_validSignerPubkeyHashes` set) signed an attestation that the
/// subject is BELOW the high-risk threshold for `jurisdiction_id`.
///
/// Trust model upgrade over 0x07 (`compliance_signed`):
///   - 0x07: one signer => one provider's "compliant" attestation
///   - 0x09: M signers => M independent providers' "compliant" attestations,
///           AND-aggregated (each must individually be below the floor)
///
/// Slot lifecycle:
///   - A slot is ACTIVE iff its public `signer_pubkey_hash` is non-zero.
///   - Active slots: signature + score-below-floor checks are enforced.
///   - Inactive slots: arbitrary witness for (pubkey, signature, signals, weights);
///     prover convention is weight_sum=1, weights=[1,0,..], signals=[0;8] so that
///     compute_risk_score does not divide by zero and verify_weight_sum is satisfied.
///
/// Public inputs (14 logical, all 32-byte aligned in the Solidity calldata):
///   - jurisdiction_id
///   - provider_set_hash       (shared across slots)
///   - config_hash             (shared across slots)
///   - timestamp
///   - meets_threshold         (always true if the proof verifies; kept for layout parity with 0x07)
///   - threshold_m             (runtime 1 <= M <= MAX_PROVIDERS_MULTI)
///   - signer_pubkey_hash_0..4 (zero means inactive)
///   - chain_id                (audit F-6)
///   - oracle_address          (audit F-6)
///   - submitter

use xochi_shared::{
    compute_risk_score,
    get_high_threshold,
    verify_weight_sum,
    MAX_PROVIDERS_MULTI,
    compute_slot_payload_hash,
    verify_slot_or_skip,
    assert_distinct_signers,
    count_active_signers,
    validate_timestamp,
};

fn main(
    // --- Private inputs ---
    // Per-slot screening data. Inactive slots: weight_sum=1, weights=[1,0,..], signals=[0;8].
    signals: [[u32; 8]; 5],
    weights: [[u32; 8]; 5],
    weight_sums: [u32; 5],
    pubkey_xs: [[u8; 32]; 5],
    pubkey_ys: [[u8; 32]; 5],
    signatures: [[u8; 64]; 5],

    // --- Public inputs ---
    jurisdiction_id: pub u8,
    provider_set_hash: pub Field,
    config_hash: pub Field,
    timestamp: pub Field,
    meets_threshold: pub bool,
    threshold_m: pub u8,
    signer_pubkey_hash_0: pub Field,
    signer_pubkey_hash_1: pub Field,
    signer_pubkey_hash_2: pub Field,
    signer_pubkey_hash_3: pub Field,
    signer_pubkey_hash_4: pub Field,
    chain_id: pub Field,
    oracle_address: pub Field,
    submitter: pub Field,
) {
    // 1. Threshold bounds
    assert(threshold_m >= 1, "threshold_m must be at least 1");
    assert(threshold_m as u32 <= MAX_PROVIDERS_MULTI, "threshold_m exceeds MAX_PROVIDERS_MULTI");

    // 2. Submitter non-zero (anti-frontrun anchor; Oracle enforces submitter == msg.sender)
    assert(submitter != 0, "submitter must be non-zero");

    // 3. Timestamp within reasonable bounds (same window as 0x07)
    validate_timestamp(timestamp);

    // 4. Pack public signer-hash inputs into an array for set-level checks.
    let signer_hashes: [Field; 5] = [
        signer_pubkey_hash_0,
        signer_pubkey_hash_1,
        signer_pubkey_hash_2,
        signer_pubkey_hash_3,
        signer_pubkey_hash_4,
    ];

    // 5. No duplicate signers among active slots.
    assert_distinct_signers(signer_hashes);

    // 6. Active count >= threshold_m.
    let active_count = count_active_signers(signer_hashes);
    assert(active_count >= threshold_m as u32, "fewer active signers than threshold_m");

    // 7. Get the jurisdiction's high-risk threshold once (shared across slots).
    let high_threshold = get_high_threshold(jurisdiction_id);

    // 8. Per-slot constraints. All 5 slots emit identical constraint shape; gating
    //    is applied to the assertions, not the constraint emission.
    for i in 0..5 {
        let active = signer_hashes[i] != 0;

        // 8a. Weight sum integrity (required for both active and inactive slots so
        //     compute_risk_score is well-defined). Prover convention for inactive:
        //     weights=[1, 0..0], weight_sum=1.
        assert(weight_sums[i] > 0, "weight_sum must be positive");
        verify_weight_sum(weights[i], weight_sums[i]);

        // 8b. Per-slot risk score. Active slot: must be below the jurisdiction floor.
        //     Inactive slot: score is 0 (zero signals), trivially below floor.
        let score = compute_risk_score(signals[i], weights[i], weight_sums[i]);
        let score_ok = score < high_threshold;
        assert((!active) | score_ok, "active slot score above jurisdiction floor");

        // 8c. Provider signature over the slot-specific Pedersen digest.
        let payload_hash = compute_slot_payload_hash(
            i,
            chain_id,
            oracle_address,
            jurisdiction_id,
            provider_set_hash,
            config_hash,
            signals[i],
            weights[i],
            timestamp,
            submitter,
        );
        verify_slot_or_skip(
            active,
            pubkey_xs[i],
            pubkey_ys[i],
            signatures[i],
            payload_hash,
            signer_hashes[i],
        );
    }

    // 9. meets_threshold is trivially true if we reached here (all gates passed for
    //    >= threshold_m slots, each individually below the floor). The public output
    //    must commit to true.
    assert(meets_threshold, "meets_threshold must be true");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Happy-path tests require valid secp256k1 signatures over the in-circuit Pedersen
// digest; those are exercised via Foundry fixtures with ethers/alloy signing keys.
// Nargo tests below cover structural failures that do not need a valid signature.

#[test(should_fail_with = "threshold_m must be at least 1")]
fn test_main_revert_threshold_zero() {
    let signals: [[u32; 8]; 5] = [[0; 8]; 5];
    let mut weights: [[u32; 8]; 5] = [[0; 8]; 5];
    for i in 0..5 {
        weights[i][0] = 1;
    }
    let weight_sums: [u32; 5] = [1, 1, 1, 1, 1];
    let zero_pk: [u8; 32] = [0; 32];
    let zero_sig: [u8; 64] = [0; 64];
    let pubkey_xs: [[u8; 32]; 5] = [zero_pk; 5];
    let pubkey_ys: [[u8; 32]; 5] = [zero_pk; 5];
    let signatures: [[u8; 64]; 5] = [zero_sig; 5];

    main(
        signals, weights, weight_sums, pubkey_xs, pubkey_ys, signatures,
        0, // EU
        0xdead,
        0xbeef,
        1700000000,
        true,
        0, // threshold_m = 0 -> revert
        0, 0, 0, 0, 0,
        1, 0xabcd1234,
        0xcafe,
    );
}

#[test(should_fail_with = "threshold_m exceeds MAX_PROVIDERS_MULTI")]
fn test_main_revert_threshold_too_high() {
    let signals: [[u32; 8]; 5] = [[0; 8]; 5];
    let mut weights: [[u32; 8]; 5] = [[0; 8]; 5];
    for i in 0..5 {
        weights[i][0] = 1;
    }
    let weight_sums: [u32; 5] = [1, 1, 1, 1, 1];
    let zero_pk: [u8; 32] = [0; 32];
    let zero_sig: [u8; 64] = [0; 64];
    let pubkey_xs: [[u8; 32]; 5] = [zero_pk; 5];
    let pubkey_ys: [[u8; 32]; 5] = [zero_pk; 5];
    let signatures: [[u8; 64]; 5] = [zero_sig; 5];

    main(
        signals, weights, weight_sums, pubkey_xs, pubkey_ys, signatures,
        0, 0xdead, 0xbeef, 1700000000, true,
        6, // > MAX_PROVIDERS_MULTI (5)
        0, 0, 0, 0, 0,
        1, 0xabcd1234, 0xcafe,
    );
}

#[test(should_fail_with = "fewer active signers than threshold_m")]
fn test_main_revert_active_count_below_threshold() {
    let signals: [[u32; 8]; 5] = [[0; 8]; 5];
    let mut weights: [[u32; 8]; 5] = [[0; 8]; 5];
    for i in 0..5 {
        weights[i][0] = 1;
    }
    let weight_sums: [u32; 5] = [1, 1, 1, 1, 1];
    let zero_pk: [u8; 32] = [0; 32];
    let zero_sig: [u8; 64] = [0; 64];
    let pubkey_xs: [[u8; 32]; 5] = [zero_pk; 5];
    let pubkey_ys: [[u8; 32]; 5] = [zero_pk; 5];
    let signatures: [[u8; 64]; 5] = [zero_sig; 5];

    main(
        signals, weights, weight_sums, pubkey_xs, pubkey_ys, signatures,
        0, 0xdead, 0xbeef, 1700000000, true,
        3, // demand 3 active
        0x11, 0x22, 0, 0, 0, // only 2 active
        1, 0xabcd1234, 0xcafe,
    );
}

#[test(should_fail_with = "duplicate signer across active slots")]
fn test_main_revert_duplicate_signers() {
    let signals: [[u32; 8]; 5] = [[0; 8]; 5];
    let mut weights: [[u32; 8]; 5] = [[0; 8]; 5];
    for i in 0..5 {
        weights[i][0] = 1;
    }
    let weight_sums: [u32; 5] = [1, 1, 1, 1, 1];
    let zero_pk: [u8; 32] = [0; 32];
    let zero_sig: [u8; 64] = [0; 64];
    let pubkey_xs: [[u8; 32]; 5] = [zero_pk; 5];
    let pubkey_ys: [[u8; 32]; 5] = [zero_pk; 5];
    let signatures: [[u8; 64]; 5] = [zero_sig; 5];

    main(
        signals, weights, weight_sums, pubkey_xs, pubkey_ys, signatures,
        0, 0xdead, 0xbeef, 1700000000, true,
        2,
        0x11, 0x11, 0, 0, 0, // duplicate active signer
        1, 0xabcd1234, 0xcafe,
    );
}

#[test(should_fail_with = "submitter must be non-zero")]
fn test_main_revert_zero_submitter() {
    let signals: [[u32; 8]; 5] = [[0; 8]; 5];
    let mut weights: [[u32; 8]; 5] = [[0; 8]; 5];
    for i in 0..5 {
        weights[i][0] = 1;
    }
    let weight_sums: [u32; 5] = [1, 1, 1, 1, 1];
    let zero_pk: [u8; 32] = [0; 32];
    let zero_sig: [u8; 64] = [0; 64];
    let pubkey_xs: [[u8; 32]; 5] = [zero_pk; 5];
    let pubkey_ys: [[u8; 32]; 5] = [zero_pk; 5];
    let signatures: [[u8; 64]; 5] = [zero_sig; 5];

    main(
        signals, weights, weight_sums, pubkey_xs, pubkey_ys, signatures,
        0, 0xdead, 0xbeef, 1700000000, true, 1,
        0, 0, 0, 0, 0,
        1, 0xabcd1234,
        0, // submitter = 0
    );
}

#[test(should_fail_with = "active slot score above jurisdiction floor")]
fn test_main_revert_active_slot_above_floor() {
    // Slot 0 active with signals producing score >= EU threshold (7100 bps).
    // signals[0]=80 (=8000 bps), weight=100 sum=100 -> score = 8000 >= 7100.
    let mut signals: [[u32; 8]; 5] = [[0; 8]; 5];
    signals[0][0] = 80;
    let mut weights: [[u32; 8]; 5] = [[0; 8]; 5];
    weights[0][0] = 100;
    for i in 1..5 {
        weights[i][0] = 1;
    }
    let weight_sums: [u32; 5] = [100, 1, 1, 1, 1];
    let zero_pk: [u8; 32] = [0; 32];
    let zero_sig: [u8; 64] = [0; 64];
    let pubkey_xs: [[u8; 32]; 5] = [zero_pk; 5];
    let pubkey_ys: [[u8; 32]; 5] = [zero_pk; 5];
    let signatures: [[u8; 64]; 5] = [zero_sig; 5];

    main(
        signals, weights, weight_sums, pubkey_xs, pubkey_ys, signatures,
        0, // EU, threshold 7100
        0xdead, 0xbeef, 1700000000, true, 1,
        0x11, 0, 0, 0, 0, // slot 0 active (signer_pubkey_hash != 0)
        1, 0xabcd1234, 0xcafe,
    );
}

// Note: `meets_threshold = false` cannot be reached without valid signatures, since
// the active_count check fires first when slots are inactive (and signature verify
// fires when slots are active but the witness has dummy keys). Exercised via Foundry
// fixtures with real ECDSA signing keys instead.
