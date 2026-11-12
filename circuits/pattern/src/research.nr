//! Circuit-binding research harness (XIP-1 remediation).
//!
//! Each `test_attack_*` passes only when the attack is REFUSED: the attacker
//! cannot make `main` accept the public inputs the on-chain consumers
//! (Oracle + SettlementRegistry) would pin, together with the result the
//! attacker wants. Each `test_honest_*` is a legitimate proof that MUST keep
//! being provable; any honest failure zeroes the metric
//! (scripts/research/circuit-metric.sh).
//!
//! Model:
//!   - `Pinned` is what the chain knows about a trade: its jurisdiction and the
//!     legs it recorded (amount, timestamp, salt as committed by each leg).
//!   - `Claim` is what the prover feeds the pattern circuit: private
//!     transactions plus the free public inputs (threshold, window, results).
//!   - `attempt` is the ONLY design-specific code: it maps (pinned, claim) to a
//!     `main` call, pinning every public input the chain would check. Attack
//!     goals and the scenarios below are fixed; `attempt` changes with the
//!     circuit's interface.
//!
//! Amounts are base units of an 18-decimal token (1 reporting unit = 1e18), so
//! realistic amounts exceed u64. Jurisdiction 0's reporting threshold is 10_000
//! units; 999_999 units is another jurisdiction's threshold.

use crate::main;
use erc8262_shared::settlement_link;

global MAXR: u32 = 32;
global UNIT: u128 = 1000000000000000000;
global PROOF_TS: u64 = 1700100000;
global HOUR: u64 = 3600;
global DAY: u64 = 86400;
global J0: u8 = 0;
global J0_THRESHOLD: u128 = 10000;
global FOREIGN_THRESHOLD: u128 = 999999;
global SUBMITTER: Field = 0xdead;
global STRUCTURING: u8 = 1;
/// Registry-derived per-trade chain seed (keccak(...) mod p on-chain).
global SEED: Field = 0x5eed;

pub struct Legs {
    amounts: [u128; MAXR],
    timestamps: [u64; MAXR],
    salts: [Field; MAXR],
    n: u32,
}

pub struct Pinned {
    jurisdiction_id: u8,
    legs: Legs,
}

pub struct Claim {
    legs: Legs,
    threshold: u128, // in base units
    window: u64,
    clean: bool,      // heuristic structuring result (true = clean)
    reportable: bool, // aggregate of the analysed legs reaches the threshold
}

// ---------------------------------------------------------------------------
// Design adapter (H1 chain over whole-unit legs; H2 threshold table; H4 aggregate)
// ---------------------------------------------------------------------------

/// Leg amount as committed in the settlement chain (H1: whole units, u64).
fn committed_amount(base_units: u128) -> u64 {
    (base_units / UNIT) as u64
}

/// The root the registry holds after recording every pinned leg: each leg's
/// compliance proof extended the chain by one link from the trade's seed.
fn registry_root(p: Pinned) -> Field {
    let mut root = SEED;
    for i in 0..MAXR {
        if i < p.legs.n {
            root = settlement_link(root, committed_amount(p.legs.amounts[i]), p.legs.timestamps[i], p.legs.salts[i]);
        }
    }
    root
}

/// H1: the registry pins settlement_seed, settlement_root and jurisdiction_id;
/// the circuit refolds the chain over the analysed legs. H2: the claimed
/// threshold must be the pinned jurisdiction's (circuit table).
fn attempt(pinned: Pinned, c: Claim) {
    let mut amounts: [u64; 16] = [0; 16];
    let mut timestamps: [u64; 16] = [0; 16];
    let mut salts: [Field; 16] = [0; 16];
    for i in 0..16 {
        amounts[i] = committed_amount(c.legs.amounts[i]);
        timestamps[i] = c.legs.timestamps[i];
        salts[i] = c.legs.salts[i];
    }
    // tx_set_hash is unpinned (Oracle: non-zero); the circuit requires it to equal
    // settlement_root, so the prover supplies the registry root.
    let root = registry_root(pinned);
    main(
        amounts,
        timestamps,
        salts,
        c.legs.n,
        STRUCTURING,
        c.clean,
        (c.threshold / UNIT) as u64,
        c.window,
        root,
        SUBMITTER,
        root,
        PROOF_TS as Field,
        SEED,
        pinned.jurisdiction_id,
        c.reportable,
    );
}

// ---------------------------------------------------------------------------
// Scenario helpers (fixed)
// ---------------------------------------------------------------------------

fn empty_legs() -> Legs {
    Legs { amounts: [0; MAXR], timestamps: [0; MAXR], salts: [0; MAXR], n: 0 }
}

/// Legs of whole-unit amounts recorded `ages[i]` seconds before the proof time.
fn legs<let K: u32>(units: [u128; K], ages: [u64; K]) -> Legs {
    let mut l = empty_legs();
    for i in 0..K {
        l.amounts[i] = units[i] * UNIT;
        l.timestamps[i] = PROOF_TS - ages[i];
        l.salts[i] = (i as Field + 1) * 7919;
    }
    l.n = K;
    l
}

fn pinned(l: Legs) -> Pinned {
    Pinned { jurisdiction_id: J0, legs: l }
}

/// The honest claim over the recorded legs.
fn honest(l: Legs, window: u64, clean: bool, reportable: bool) -> Claim {
    Claim { legs: l, threshold: J0_THRESHOLD * UNIT, window, clean, reportable }
}

// ---------------------------------------------------------------------------
// Honest proofs (must keep working)
// ---------------------------------------------------------------------------

#[test]
fn test_honest_two_legs_clean() {
    let l = legs([500, 1200], [600, 300]);
    attempt(pinned(l), honest(l, DAY, true, false));
}

#[test]
fn test_honest_sixteen_legs_clean() {
    let mut l = empty_legs();
    for i in 0..16 {
        l.amounts[i] = (100 + i as u128) * UNIT;
        l.timestamps[i] = PROOF_TS - 60 * (16 - i as u64);
        l.salts[i] = i as Field + 11;
    }
    l.n = 16;
    attempt(pinned(l), honest(l, DAY, true, false));
}

/// A split that IS structured can be proven (and reported) honestly.
#[test]
fn test_honest_structuring_reported() {
    let l = legs([9500, 9600, 9700], [900, 600, 300]);
    attempt(pinned(l), honest(l, DAY, false, true));
}

/// Legitimate large split: no leg near the threshold, aggregate above it.
#[test]
fn test_honest_large_split() {
    let l = legs([6000, 6000], [600, 300]);
    attempt(pinned(l), honest(l, DAY, true, true));
}

#[test]
fn test_honest_legs_over_two_days() {
    let l = legs([500, 700, 900], [2 * DAY, DAY, 600]);
    attempt(pinned(l), honest(l, 3 * DAY, true, false));
}

/// Amounts are not whole units.
#[test]
fn test_honest_fractional_amounts() {
    let mut l = legs([1234, 4321], [600, 300]);
    l.amounts[0] += 500000000000000000;
    l.amounts[1] += 1;
    attempt(pinned(l), honest(l, DAY, true, false));
}

// ---------------------------------------------------------------------------
// Attacks (pass = refused)
// ---------------------------------------------------------------------------

/// Sanity: lie about the result over the real legs.
#[test(should_fail)]
fn test_attack_result_lie() {
    let l = legs([9500, 9600, 9700], [900, 600, 300]);
    attempt(pinned(l), honest(l, DAY, true, false));
}

/// settlement_root names the real legs; the analysed amounts are unrelated.
#[test(should_fail)]
fn test_attack_unrelated_amounts() {
    let real = legs([9500, 9600, 9700], [900, 600, 300]);
    let fake = legs([500, 600, 700], [900, 600, 300]);
    attempt(pinned(real), honest(fake, DAY, true, false));
}

/// Real legs, but analysed against another jurisdiction's (higher) threshold.
#[test(should_fail)]
fn test_attack_foreign_threshold() {
    let l = legs([9500, 9600, 9700], [900, 600, 300]);
    let mut c = honest(l, DAY, true, false);
    c.threshold = FOREIGN_THRESHOLD * UNIT;
    attempt(pinned(l), c);
}

/// Prover rescales the legs (wrong unit: /10) before analysing them.
#[test(should_fail)]
fn test_attack_unit_rescale() {
    let real = legs([9500, 9600, 9700], [900, 600, 300]);
    let mut fake = real;
    for i in 0..3 {
        fake.amounts[i] = real.amounts[i] / 10;
    }
    attempt(pinned(real), honest(fake, DAY, true, false));
}

/// Wei amounts above 2^64 analysed after truncation to u64.
#[test(should_fail)]
fn test_attack_u64_truncation() {
    let real = legs([9500, 9600, 9700], [900, 600, 300]);
    let mut fake = real;
    for i in 0..3 {
        fake.amounts[i] = real.amounts[i] % 18446744073709551616;
    }
    attempt(pinned(real), honest(fake, DAY, true, false));
}

/// 32 legs recorded (16 structured); the proof analyses the 16 clean ones.
#[test(should_fail)]
fn test_attack_more_legs_than_capacity() {
    let mut real = empty_legs();
    let mut fake = empty_legs();
    for i in 0..32 {
        real.amounts[i] = if i < 16 { 100 * UNIT } else { 9500 * UNIT };
        real.timestamps[i] = PROOF_TS - 60 * (32 - i as u64);
        real.salts[i] = i as Field + 1;
    }
    real.n = 32;
    for i in 0..16 {
        fake.amounts[i] = real.amounts[i];
        fake.timestamps[i] = real.timestamps[i];
        fake.salts[i] = real.salts[i];
    }
    fake.n = 16;
    attempt(pinned(real), honest(fake, DAY, true, false));
}

/// Structured legs dropped from the analysis.
#[test(should_fail)]
fn test_attack_leg_omission() {
    let real = legs([100, 9500, 9600], [900, 600, 300]);
    let mut fake = real;
    fake.amounts[1] = 0;
    fake.amounts[2] = 0;
    fake.timestamps[1] = 0;
    fake.timestamps[2] = 0;
    fake.salts[1] = 0;
    fake.salts[2] = 0;
    fake.n = 1;
    attempt(pinned(real), honest(fake, DAY, true, false));
}

/// Fake small transactions padded into the analysis to dilute the cluster.
#[test(should_fail)]
fn test_attack_fake_dilution() {
    let real = legs([9500, 9600], [600, 300]);
    let fake = legs([9500, 9600, 1, 1, 1], [600, 300, 200, 100, 50]);
    attempt(pinned(real), honest(fake, DAY, true, false));
}

/// Real tiny legs dilute the heuristic; the split (19_103 units) must not
/// finalize as non-reportable.
#[test(should_fail)]
fn test_attack_real_dilution() {
    let l = legs([9500, 9600, 1, 1, 1], [600, 300, 200, 100, 50]);
    attempt(pinned(l), honest(l, DAY, true, false));
}

/// Legs recorded over 3 days relabelled into a 1-day window.
#[test(should_fail)]
fn test_attack_relabel_into_window() {
    let real = legs([500, 700], [3 * DAY, HOUR]);
    let fake = legs([500, 700], [2 * HOUR, HOUR]);
    attempt(pinned(real), honest(fake, DAY, true, false));
}

/// Fractional parts truncated away: 5_000.6 + 4_999.6 = 10_000.2 units reaches
/// the threshold, but any whole-unit commitment sums to 9_999.
#[test(should_fail)]
fn test_attack_fractional_truncation() {
    let mut l = legs([5000, 4999], [600, 300]);
    l.amounts[0] += 600000000000000000;
    l.amounts[1] += 600000000000000000;
    attempt(pinned(l), honest(l, DAY, true, false));
}
