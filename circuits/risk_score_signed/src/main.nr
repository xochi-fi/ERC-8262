/// Provider-signed risk-score circuit (audit finding I-1).
///
/// Identical semantics to `risk_score`, but additionally verifies a secp256k1
/// ECDSA signature over `(chain_id, oracle_address, provider_set_hash, signals,
/// weights, timestamp, submitter)` produced by an Oracle-registered provider key,
/// under the RISK_SCORE_SIGNED domain tag. Closes the "honest signals" gap for the
/// standalone risk-score primitive used in custom integrations.
///
/// The signed `timestamp` is a public input (as in `compliance_signed`), so the
/// Oracle can freshness-check it: a provider signature is only usable within the
/// Oracle's proof-age window. The domain tag (DOMAIN_RISK_SIGNED_SIGNALS) is
/// distinct from COMPLIANCE_SIGNED's, so a bundle signed for 0x07 cannot mint a
/// 0x08 proof (review #5).
///
/// Public inputs:
///   - proof_type: 0x01 (threshold) or 0x02 (range)
///   - direction: for threshold, 1=GT, 2=LT
///   - bound_lower, bound_upper: bounds (basis points)
///   - result: boolean
///   - config_hash: hash of published weight configuration
///   - provider_set_hash: commitment to which providers were used
///   - timestamp: the timestamp the provider signed; the Oracle's proof time
///   - signer_pubkey_hash: Pedersen commitment to the provider signer pubkey
///   - chain_id: EVM chain ID, committed in the signed digest (audit F-6)
///   - oracle_address: deployment address of the consuming Oracle (audit F-6)
///   - submitter: address of the authorized proof submitter
///
/// Private inputs:
///   - signals, weights, weight_sum, provider_ids, num_providers (as in `risk_score`)
///   - signature: 64-byte secp256k1 ECDSA signature (r || s)
///   - pubkey_x, pubkey_y: 32-byte big-endian secp256k1 pubkey coordinates

use erc8262_shared::{
    compute_risk_score,
    verify_weight_sum,
    compute_config_hash,
    compute_provider_set_hash,
    validate_timestamp,
    validate_provider_slots,
    compute_signed_payload_hash,
    verify_provider_signed_signals,
    DOMAIN_RISK_SIGNED_SIGNALS,
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

    // --- Public ---
    proof_type: pub u8,
    direction: pub u8,
    bound_lower: pub u32,
    bound_upper: pub u32,
    result: pub bool,
    config_hash: pub Field,
    provider_set_hash: pub Field,
    timestamp: pub Field,
    signer_pubkey_hash: pub Field,
    // Audit F-6: bind the signed digest to a specific deployment.
    chain_id: pub Field,
    oracle_address: pub Field,
    submitter: pub Field,
) {
    // 1. Validate inputs
    assert(weight_sum > 0, "Weight sum must be positive");
    assert(
        (proof_type == PROOF_THRESHOLD) | (proof_type == PROOF_RANGE),
        "Invalid proof type",
    );

    // 2. Validate provider count + slot invariants
    validate_provider_slots(signals, weights, provider_ids, num_providers);

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

    // 7. Timestamp must be within reasonable bounds (freshness is the Oracle's job)
    validate_timestamp(timestamp);

    // 8. Anchor submitter
    assert(submitter != 0, "submitter must be non-zero");

    // 9. *** Provider signature verification (audit I-1 remediation). ***
    // The digest commits to the public timestamp under the 0x08 domain tag.
    let payload_hash = compute_signed_payload_hash(
        DOMAIN_RISK_SIGNED_SIGNALS,
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
        zero_sig, zero_x, zero_y,
        PROOF_THRESHOLD, DIRECTION_GT, 5000, 0, true,
        config, provider_hash,
        1700000000, // timestamp
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
        zero_sig, zero_x, zero_y,
        PROOF_THRESHOLD, DIRECTION_GT, 5000, 0, true, // 2000 > 5000 false; claim true
        config, provider_hash,
        1700000000, // timestamp
        0,
        1,          // chain_id
        0xabcd1234, // oracle_address
        0xdead,
    );
}

#[test(should_fail_with = "Timestamp before 2021")]
fn test_main_revert_timestamp_before_2021() {
    let signals = [25, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let provider_ids: [Field; 8] = [1, 0, 0, 0, 0, 0, 0, 0];

    main(
        signals, weights, 100, provider_ids, 1,
        FIXTURE_SIG_RISK_SIGNED, FIXTURE_PUBKEY_X, FIXTURE_PUBKEY_Y,
        PROOF_THRESHOLD, DIRECTION_LT, 5000, 0, true,
        compute_config_hash(weights), compute_provider_set_hash(provider_ids, weights),
        1000000000, // 2001: fails the range check before the signature check
        FIXTURE_SIGNER_PUBKEY_HASH, FIXTURE_CHAIN_ID, FIXTURE_ORACLE, FIXTURE_SUBMITTER,
    );
}

// ---------------------------------------------------------------------------
// Signed-bundle tests (review #5). One provider bundle, signed twice with the
// same key: once under the 0x07 domain (DOMAIN_SIGNED_SIGNALS) and once under the
// 0x08 domain (DOMAIN_RISK_SIGNED_SIGNALS). Bundle: signals [25], weights [100],
// provider_ids [1], chain_id 31337, oracle_address = the Oracle IntegrationTest
// deploys, timestamp 1700000000, submitter 0xdead. The 0x08 signature is also the
// witness in Prover.toml (the Foundry RISK_SCORE_SIGNED fixture).
//
// Signer: secp256k1 key keccak256("erc8262-integration-fixture-provider-signer"),
// low-S signatures over the 32-byte big-endian digest (xochi-sdk signSignals).
// ---------------------------------------------------------------------------

global FIXTURE_CHAIN_ID: Field = 31337;
global FIXTURE_ORACLE: Field = 0x2e234dae75c793f67a35089c9d99245e1c58470b;
global FIXTURE_TIMESTAMP: Field = 1700000000;
global FIXTURE_SUBMITTER: Field = 0xdead;
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

/// Prove "risk < 50%" for the fixture bundle with the given signature and timestamp.
fn prove_fixture_bundle(signature: [u8; 64], timestamp: Field) {
    let signals = [25, 0, 0, 0, 0, 0, 0, 0]; // score = 2500 bps
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let provider_ids: [Field; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
    main(
        signals, weights, 100, provider_ids, 1,
        signature, FIXTURE_PUBKEY_X, FIXTURE_PUBKEY_Y,
        PROOF_THRESHOLD, DIRECTION_LT, 5000, 0, true,
        compute_config_hash(weights), compute_provider_set_hash(provider_ids, weights),
        timestamp,
        FIXTURE_SIGNER_PUBKEY_HASH, FIXTURE_CHAIN_ID, FIXTURE_ORACLE, FIXTURE_SUBMITTER,
    );
}

#[test]
fn test_main_accepts_risk_signed_bundle() {
    prove_fixture_bundle(FIXTURE_SIG_RISK_SIGNED, FIXTURE_TIMESTAMP);
}

#[test(should_fail_with = "invalid provider signature on signals")]
fn test_main_rejects_compliance_signed_bundle() {
    // Same key, same bundle, but signed for COMPLIANCE_SIGNED (0x07): the 0x08
    // domain tag makes the digests differ, so the signature does not verify.
    prove_fixture_bundle(FIXTURE_SIG_COMPLIANCE_SIGNED, FIXTURE_TIMESTAMP);
}

#[test(should_fail_with = "invalid provider signature on signals")]
fn test_main_rejects_redated_bundle() {
    // A signature from 1700000000 relabelled with a later (fresh-looking) public
    // timestamp: the signed digest commits to the timestamp, so it no longer
    // verifies. The Oracle's freshness window therefore bounds the signature's life.
    prove_fixture_bundle(FIXTURE_SIG_RISK_SIGNED, FIXTURE_TIMESTAMP + 86400);
}
