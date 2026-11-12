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
/// Public inputs (16 logical, all 32-byte aligned in the Solidity calldata):
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
///   - settlement_link_in / settlement_link_out (XIP-1): one link of a split
///     settlement's chain, link_out = settlement_link(link_in, leg_amount, timestamp,
///     leg_salt). SettlementRegistry accepts the leg only if link_in is the trade's
///     current root and then stores link_out. Standalone use: any link_in. Not part
///     of any slot's signed digest.
///
/// Private inputs (known only to prover):
///   - signals, weights, weight_sums: per-slot screening data
///   - pubkey_xs, pubkey_ys, signatures: per-slot provider keys and ECDSA signatures
///   - leg_amount / leg_salt: the settlement leg's amount and blinding (XIP-1)

use erc8262_shared::{
    compute_risk_score,
    get_high_threshold,
    verify_weight_sum,
    MAX_PROVIDERS_MULTI,
    compute_slot_payload_hash,
    verify_slot_or_skip,
    assert_distinct_signers,
    count_active_signers,
    validate_timestamp,
    settlement_link,
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
    leg_amount: u64,             // XIP-1: settlement leg amount
    leg_salt: Field,             // XIP-1: settlement leg blinding

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
    settlement_link_in: pub Field,  // XIP-1: settlement chain root before this leg
    settlement_link_out: pub Field, // XIP-1: settlement chain root after this leg
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

    // 10. XIP-1: extend the settlement chain by this leg (timestamp = proof time).
    let link = settlement_link(settlement_link_in, leg_amount, timestamp as u64, leg_salt);
    assert(link == settlement_link_out, "Settlement link mismatch");
}

/// Pre-XIP-1 call shape for the tests: standalone use (link_in 0, zero leg).
fn run(
    signals: [[u32; 8]; 5],
    weights: [[u32; 8]; 5],
    weight_sums: [u32; 5],
    pubkey_xs: [[u8; 32]; 5],
    pubkey_ys: [[u8; 32]; 5],
    signatures: [[u8; 64]; 5],
    jurisdiction_id: u8,
    provider_set_hash: Field,
    config_hash: Field,
    timestamp: Field,
    meets_threshold: bool,
    threshold_m: u8,
    signer_pubkey_hash_0: Field,
    signer_pubkey_hash_1: Field,
    signer_pubkey_hash_2: Field,
    signer_pubkey_hash_3: Field,
    signer_pubkey_hash_4: Field,
    chain_id: Field,
    oracle_address: Field,
    submitter: Field,
) {
    let link_out = settlement_link(0, 0, timestamp as u64, 0);
    main(
        signals, weights, weight_sums, pubkey_xs, pubkey_ys, signatures, 0, 0,
        jurisdiction_id, provider_set_hash, config_hash, timestamp, meets_threshold,
        threshold_m,
        signer_pubkey_hash_0, signer_pubkey_hash_1, signer_pubkey_hash_2,
        signer_pubkey_hash_3, signer_pubkey_hash_4,
        chain_id, oracle_address, submitter,
        0, link_out,
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// The structural-failure tests below need no valid signature. The settlement-leg
// tests at the end reuse Prover.toml's signed 2-of-5 bundle.

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

    run(
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

    run(
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

    run(
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

    run(
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

    run(
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

    run(
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

// ---------------------------------------------------------------------------
// Settlement-leg tests (XIP-1). The witness is Prover.toml's US 2-of-5 bundle (slots
// 0 and 2 active, signed via @xochi/provider signSlotPayload; see Prover.toml for
// provenance). Inactive slots carry pubkey 2G and signature r = s = 1.
// ---------------------------------------------------------------------------

global FIXTURE_PUBKEY_X_0: [u8; 32] = [
    32, 200, 84, 126, 134, 190, 235, 89, 194, 183, 197, 14, 72, 83, 155, 145, 70, 127, 150, 181,
    178, 60, 72, 184, 9, 78, 30, 217, 164, 212, 226, 66,
];
global FIXTURE_PUBKEY_Y_0: [u8; 32] = [
    45, 74, 60, 178, 139, 138, 55, 189, 66, 187, 156, 255, 146, 98, 182, 228, 212, 219, 184, 140,
    139, 128, 126, 35, 147, 85, 247, 92, 95, 166, 66, 144,
];
global FIXTURE_PUBKEY_X_2: [u8; 32] = [
    253, 204, 83, 103, 21, 78, 54, 83, 31, 229, 89, 136, 198, 83, 192, 36, 97, 182, 29, 228, 19,
    233, 173, 0, 15, 134, 197, 86, 168, 195, 17, 190,
];
global FIXTURE_PUBKEY_Y_2: [u8; 32] = [
    15, 246, 126, 99, 123, 111, 128, 191, 152, 137, 238, 22, 206, 92, 15, 114, 232, 218, 126,
    206, 193, 36, 184, 169, 129, 187, 231, 144, 86, 75, 30, 6,
];
global PAD_PUBKEY_X: [u8; 32] = [
    198, 4, 127, 148, 65, 237, 125, 109, 48, 69, 64, 110, 149, 192, 124, 216, 92, 119, 142, 75,
    140, 239, 60, 167, 171, 172, 9, 185, 92, 112, 158, 229,
];
global PAD_PUBKEY_Y: [u8; 32] = [
    26, 225, 104, 254, 166, 61, 195, 57, 163, 197, 132, 25, 70, 108, 234, 238, 247, 246, 50, 101,
    50, 102, 208, 225, 35, 100, 49, 169, 80, 207, 229, 42,
];
global FIXTURE_SIG_0: [u8; 64] = [
    204, 73, 40, 53, 125, 29, 157, 48, 165, 157, 193, 191, 52, 146, 252, 105, 82, 168, 151, 186,
    220, 169, 12, 75, 41, 199, 95, 153, 214, 33, 75, 64, 123, 156, 210, 17, 96, 88, 221, 84, 247,
    242, 142, 57, 218, 156, 15, 172, 96, 242, 138, 212, 197, 181, 83, 199, 103, 184, 237, 244,
    242, 164, 224, 53,
];
global FIXTURE_SIG_2: [u8; 64] = [
    88, 175, 244, 218, 171, 130, 90, 176, 10, 110, 162, 173, 198, 210, 91, 167, 35, 0, 184, 82,
    108, 214, 1, 96, 247, 50, 122, 115, 33, 187, 127, 37, 127, 160, 104, 4, 235, 108, 16, 182, 1,
    18, 206, 203, 160, 162, 96, 114, 254, 136, 27, 176, 160, 192, 26, 121, 170, 113, 246, 44,
    189, 55, 71, 68,
];

/// Prove the fixture 2-of-5 bundle as one settlement leg.
fn fixture_leg(link_in: Field, leg_amount: u64, leg_salt: Field, link_out: Field) {
    let active_signals: [u32; 8] = [25, 0, 0, 0, 0, 0, 0, 0];
    let pad_signals: [u32; 8] = [0; 8];
    let active_weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let pad_weights: [u32; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
    let mut pad_sig: [u8; 64] = [0; 64];
    pad_sig[31] = 1;
    pad_sig[63] = 1;

    main(
        [active_signals, pad_signals, active_signals, pad_signals, pad_signals],
        [active_weights, pad_weights, active_weights, pad_weights, pad_weights],
        [100, 1, 100, 1, 1],
        [FIXTURE_PUBKEY_X_0, PAD_PUBKEY_X, FIXTURE_PUBKEY_X_2, PAD_PUBKEY_X, PAD_PUBKEY_X],
        [FIXTURE_PUBKEY_Y_0, PAD_PUBKEY_Y, FIXTURE_PUBKEY_Y_2, PAD_PUBKEY_Y, PAD_PUBKEY_Y],
        [FIXTURE_SIG_0, pad_sig, FIXTURE_SIG_2, pad_sig, pad_sig],
        leg_amount,
        leg_salt,
        1, // US
        0x14b6becf762f80a24078e62fc9a7eca246b8e406d19962dda817b173f30a94b2, // provider_set_hash
        0x18574f427f33c6c77af53be06544bd749c9a1db855599d950af61ea613df8405, // config_hash
        1700000000,
        true,
        2, // threshold_m
        0x294fc7a4edbc711b1c3ceceb89474957aea2974dbf3d27efe759a1ecef35d6dc,
        0,
        0x2eb905640e16a7a7cb2fc08f412e4db744621a9b8ea6c760cedeefc5004e1b20,
        0,
        0,
        31337,                                      // chain_id
        0x2e234dae75c793f67a35089c9d99245e1c58470b, // oracle_address
        0xdead,
        link_in,
        link_out,
    );
}

#[test]
fn test_leg_extends_settlement_chain() {
    let link_out = settlement_link(0x5eed, 9500, 1700000000, 42);
    fixture_leg(0x5eed, 9500, 42, link_out);
}

#[test(should_fail_with = "Settlement link mismatch")]
fn test_leg_rejects_link_for_other_amount() {
    let link_out = settlement_link(0x5eed, 9500, 1700000000, 42);
    fixture_leg(0x5eed, 950, 42, link_out);
}

#[test(should_fail_with = "Settlement link mismatch")]
fn test_leg_rejects_link_from_other_root() {
    let link_out = settlement_link(0x5eed, 9500, 1700000000, 42);
    fixture_leg(0x5eee, 9500, 42, link_out);
}
