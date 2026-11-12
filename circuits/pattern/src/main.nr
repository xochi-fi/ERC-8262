/// Pattern detection circuit (anti-structuring)
///
/// Proves that a set of recent transactions does NOT exhibit structuring
/// patterns (deliberate splitting of large transactions to avoid reporting
/// thresholds), without revealing the transaction amounts or count.
///
/// Structuring indicators checked:
/// 1. No cluster of amounts just below a reporting threshold
/// 2. No suspicious velocity (too many transactions in a short window)
/// 3. No round-amount concentration
///
/// Public inputs:
///   - analysis_type: which pattern was analyzed (1=structuring, 2=velocity, 3=round amounts)
///   - result: boolean (true = no structuring detected, i.e. clean)
///   - reporting_threshold: the jurisdiction's reporting threshold; the circuit asserts it
///                          equals shared::get_reporting_threshold(jurisdiction_id)
///   - time_window: the analysis window in seconds; every active transaction
///                  lies in [timestamp - time_window, timestamp]
///   - tx_set_hash: commitment to the transaction set analyzed
///   - submitter: address of the authorized proof submitter (anti-frontrun)
///   - settlement_root: XIP-1 binding. The circuit folds the settlement chain from
///                      `settlement_seed` over the analysed transactions
///                      (shared::settlement) and asserts the result equals this
///                      value. SettlementRegistry pins it to the chain its legs'
///                      compliance proofs built, so the analysis covers exactly the
///                      recorded legs with their committed amounts and timestamps.
///   - timestamp: prover-chosen proof time; the Oracle enforces freshness
///                (MAX_PROOF_AGE, no future timestamps). The circuit binds every
///                active transaction timestamp into [timestamp - time_window, timestamp],
///                so the analysed set is recent. With a registry-pinned settlement_root
///                the timestamps are the legs' committed ones, so they cannot be
///                relabelled; standalone (unbound) use is a consistency rule only.
///                Appended last so settlement_root keeps its index.
///   - settlement_seed: chain start; SettlementRegistry pins it to its per-trade seed
///                      (standalone use: any value, settlement_root is then unbound).
///   - jurisdiction_id: trade jurisdiction (SettlementRegistry pins it).
///   - aggregate_reportable: whether the analysed transactions sum to at least the
///                           reporting threshold.
///
/// Private inputs:
///   - amounts: transaction amounts
///   - timestamps: transaction timestamps
///   - salts: per-leg blinding committed in the settlement chain
///   - num_transactions: how many are active

use erc8262_shared::{
    MAX_TRANSACTIONS, compute_tx_set_hash, fold_settlement_root, get_reporting_threshold,
    validate_timestamp,
};

mod research;

/// Structuring: amounts clustered just below threshold
global ANALYSIS_STRUCTURING: u8 = 1;
/// Velocity: too many transactions in time window
global ANALYSIS_VELOCITY: u8 = 2;
/// Round amounts: suspicious concentration of round numbers
global ANALYSIS_ROUND_AMOUNT: u8 = 3;

/// Percentage of threshold that defines "just below" (90%)
global STRUCTURING_FLOOR_PCT: u64 = 90;
/// Maximum allowed transactions in a time window before flagging
global MAX_VELOCITY: u32 = 10;
/// Round amount divisor (amounts divisible by this are "round")
global ROUND_DIVISOR: u64 = 1000;
/// Maximum percentage of round amounts before flagging
global MAX_ROUND_PCT: u32 = 80;

fn main(
    // --- Private ---
    amounts: [u64; 16],
    timestamps: [u64; 16],
    salts: [Field; 16],
    num_transactions: u32,

    // --- Public ---
    analysis_type: pub u8,
    result: pub bool,              // true = clean (no structuring)
    reporting_threshold: pub u64,  // jurisdiction reporting threshold
    time_window: pub u64,          // analysis window in seconds
    tx_set_hash: pub Field,        // commitment to the analyzed set
    submitter: pub Field,          // authorized submitter address (oracle enforces == msg.sender)
    settlement_root: pub Field,    // XIP-1: settlement chain folded over the analysed set
    timestamp: pub Field,          // prover-chosen; Oracle enforces freshness
    settlement_seed: pub Field,    // XIP-1: chain start (registry-pinned per trade)
    jurisdiction_id: pub u8,       // XIP-1: trade jurisdiction (registry-pinned)
    aggregate_reportable: pub bool, // XIP-1: sum of analysed amounts >= threshold
) {
    // Validate inputs
    assert(num_transactions >= 1, "At least one transaction required");
    assert(num_transactions <= MAX_TRANSACTIONS, "Too many transactions");
    // XIP-1: the threshold is the pinned jurisdiction's, from the circuit table.
    assert(
        reporting_threshold == get_reporting_threshold(jurisdiction_id),
        "Threshold is not the jurisdiction's",
    );
    let _ = aggregate_reportable; // constrained by a later XIP-1 hypothesis
    assert(time_window > 0, "Time window must be positive");

    // Timestamp must be within reasonable bounds (freshness is the Oracle's job)
    validate_timestamp(timestamp);
    let proof_ts = timestamp as u64;

    // Anchor submitter as a public input (oracle enforces submitter == msg.sender).
    assert(submitter != 0, "submitter must be non-zero");

    // Validate active slots have sane timestamps inside the analysis window ending at
    // the proof timestamp (so, for an honest prover, Oracle freshness implies recent
    // transactions); ensure inactive slots are zeroed
    for i in 0..16 {
        if (i as u32) < num_transactions {
            validate_timestamp(timestamps[i] as Field);
            assert(timestamps[i] <= proof_ts, "Transaction after proof timestamp");
            assert(proof_ts - timestamps[i] <= time_window, "Transaction outside time window");
        } else {
            assert(amounts[i] == 0, "Inactive amount must be zero");
            assert(timestamps[i] == 0, "Inactive timestamp must be zero");
            assert(salts[i] == 0, "Inactive salt must be zero");
        }
    }

    // XIP-1: the analysed set is exactly the settlement chain's legs.
    let root = fold_settlement_root(settlement_seed, amounts, timestamps, salts, num_transactions);
    assert(root == settlement_root, "Settlement root mismatch");

    // Verify tx_set_hash
    let computed_hash = compute_tx_set_hash(amounts, timestamps);
    assert(computed_hash == tx_set_hash, "Transaction set hash mismatch");

    // Run the appropriate analysis
    if analysis_type == ANALYSIS_STRUCTURING {
        let clean = check_structuring(amounts, num_transactions, reporting_threshold);
        assert(result == clean, "Structuring result mismatch");
    } else if analysis_type == ANALYSIS_VELOCITY {
        let clean = check_velocity(timestamps, num_transactions, time_window);
        assert(result == clean, "Velocity result mismatch");
    } else if analysis_type == ANALYSIS_ROUND_AMOUNT {
        let clean = check_round_amounts(amounts, num_transactions);
        assert(result == clean, "Round amount result mismatch");
    } else {
        assert(false, "Invalid analysis type");
    }
}

/// Check for structuring: count amounts in [threshold*90%, threshold)
/// If more than 50% of transactions are in this range, flag as structuring
fn check_structuring(
    amounts: [u64; 16],
    num_transactions: u32,
    reporting_threshold: u64,
) -> bool {
    let floor = (reporting_threshold * STRUCTURING_FLOOR_PCT) / 100;
    let mut suspicious_count: u32 = 0;

    for i in 0..16 {
        if (i as u32) < num_transactions {
            let amt = amounts[i];
            if (amt >= floor) & (amt < reporting_threshold) {
                suspicious_count += 1;
            }
        }
    }

    // Clean if fewer than half are in the suspicious range
    let half = (num_transactions + 1) / 2;
    suspicious_count < half
}

/// Check velocity: ensure not too many transactions in the time window.
/// `main` already binds every active transaction into [timestamp - time_window, timestamp]
/// and `latest <= timestamp`, so every active transaction passes the `window_start` filter
/// below and the check reduces to `num_transactions <= MAX_VELOCITY` there. The filter only
/// matters for direct calls (the unit tests); it is kept so the verifier stays unchanged.
fn check_velocity(
    timestamps: [u64; 16],
    num_transactions: u32,
    time_window: u64,
) -> bool {
    // Find the latest timestamp
    let mut latest: u64 = 0;
    for i in 0..16 {
        if (i as u32) < num_transactions {
            if timestamps[i] > latest {
                latest = timestamps[i];
            }
        }
    }

    // Count transactions within the window
    let window_start = if latest > time_window { latest - time_window } else { 0 };
    let mut count: u32 = 0;

    for i in 0..16 {
        if (i as u32) < num_transactions {
            if timestamps[i] >= window_start {
                count += 1;
            }
        }
    }

    count <= MAX_VELOCITY
}

/// Check for suspicious concentration of round amounts
fn check_round_amounts(
    amounts: [u64; 16],
    num_transactions: u32,
) -> bool {
    let mut round_count: u32 = 0;

    for i in 0..16 {
        if (i as u32) < num_transactions {
            if amounts[i] % ROUND_DIVISOR == 0 {
                round_count += 1;
            }
        }
    }

    // Clean if round amounts are less than MAX_ROUND_PCT of total
    (round_count * 100) < (num_transactions * MAX_ROUND_PCT)
}

#[test]
fn test_clean_structuring() {
    let amounts: [u64; 16] = [500, 1200, 3000, 7500, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let clean = check_structuring(amounts, 4, 10000);
    assert(clean == true);
}

#[test]
fn test_detected_structuring() {
    // 3 of 4 amounts are just below the 10000 threshold (in 9000-9999 range)
    let amounts: [u64; 16] = [9500, 9800, 9200, 500, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let clean = check_structuring(amounts, 4, 10000);
    assert(clean == false);
}

#[test]
fn test_clean_velocity() {
    let timestamps: [u64; 16] = [1700000000, 1700000500, 1700001000, 1700001500, 1700002000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let clean = check_velocity(timestamps, 5, 3600);
    assert(clean == true);
}

#[test]
fn test_clean_round_amounts() {
    // Only 1 of 4 is a round amount (3000), which is 25% < 80%
    let amounts: [u64; 16] = [1234, 5678, 3000, 9876, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let clean = check_round_amounts(amounts, 4);
    assert(clean == true);
}

#[test]
fn test_main_structuring_clean() {
    let amounts: [u64; 16] = [500, 1200, 3000, 7500, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 4, ANALYSIS_STRUCTURING, true, 10000, 3600, tx_hash, 0xdead, 0, 1700003600);
}

#[test]
fn test_main_velocity_clean() {
    let amounts: [u64; 16] = [100, 200, 300, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700000500, 1700001000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 3, ANALYSIS_VELOCITY, true, 10000, 3600, tx_hash, 0xdead, 0, 1700003600);
}

#[test]
fn test_main_round_amounts_clean() {
    let amounts: [u64; 16] = [1234, 5678, 3000, 9876, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 4, ANALYSIS_ROUND_AMOUNT, true, 10000, 3600, tx_hash, 0xdead, 0, 1700003600);
}

#[test]
fn test_main_structuring_detected() {
    // 3 of 4 amounts in [9000, 10000) -> structuring detected
    let amounts: [u64; 16] = [9500, 9800, 9200, 500, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 4, ANALYSIS_STRUCTURING, false, 10000, 3600, tx_hash, 0xdead, 0, 1700003600);
}

#[test]
fn test_structuring_threshold_boundary() {
    // amounts == threshold, NOT < threshold, so not in suspicious range
    let amounts: [u64; 16] = [10000, 10000, 10000, 10000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 4, ANALYSIS_STRUCTURING, true, 10000, 3600, tx_hash, 0xdead, 0, 1700003600);
}

#[test]
fn test_velocity_exactly_max() {
    let amounts: [u64; 16] = [100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700000100, 1700000200, 1700000300, 1700000400, 1700000500, 1700000600, 1700000700, 1700000800, 1700000900, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 10, ANALYSIS_VELOCITY, true, 10000, 3600, tx_hash, 0xdead, 0, 1700003600);
}

#[test]
fn test_velocity_exceeds_max() {
    let amounts: [u64; 16] = [100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700000100, 1700000200, 1700000300, 1700000400, 1700000500, 1700000600, 1700000700, 1700000800, 1700000900, 1700001000, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 11, ANALYSIS_VELOCITY, false, 10000, 3600, tx_hash, 0xdead, 0, 1700003600);
}

#[test]
fn test_round_amounts_all_round() {
    // 4/4 round amounts -> round_count*100=400, num*80=320, 400 < 320 is false -> not clean
    let amounts: [u64; 16] = [1000, 2000, 3000, 4000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 4, ANALYSIS_ROUND_AMOUNT, false, 10000, 3600, tx_hash, 0xdead, 0, 1700003600);
}

/// XIP-1: the threshold comes from the jurisdiction table (EU = 10_000), so the
/// former MAX_REPORTING_THRESHOLD overflow-boundary cases no longer apply; these
/// keep the single-transaction floor boundary at the table threshold.
#[test]
fn test_structuring_single_tx_below_floor() {
    // floor = 10000 * 90 / 100 = 9000; amount 8999 < floor -> clean
    let amounts: [u64; 16] = [8999, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 1, ANALYSIS_STRUCTURING, true, 10000, 3600, tx_hash, 0xdead, 0, 1700003600);
}

#[test]
fn test_structuring_single_tx_at_floor_suspicious() {
    // amount == floor (9000) -> in [floor, threshold) -> 1 of 1 suspicious -> not clean
    let amounts: [u64; 16] = [9000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 1, ANALYSIS_STRUCTURING, false, 10000, 3600, tx_hash, 0xdead, 0, 1700003600);
}

#[test(should_fail_with = "Threshold is not the jurisdiction's")]
fn test_main_revert_threshold_not_jurisdictions() {
    let amounts: [u64; 16] = [500, 1200, 3000, 7500, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 4, ANALYSIS_STRUCTURING, true, 20000, 3600, tx_hash, 0xdead, 0, 1700003600);
}

#[test(should_fail_with = "Timestamp before 2021")]
fn test_main_revert_timestamp_before_2021() {
    let amounts: [u64; 16] = [500, 1200, 3000, 7500, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 4, ANALYSIS_STRUCTURING, true, 10000, 3600, tx_hash, 0xdead, 0, 1000);
}

#[test(should_fail_with = "Timestamp unreasonably far future")]
fn test_main_revert_timestamp_far_future() {
    let amounts: [u64; 16] = [500, 1200, 3000, 7500, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 4, ANALYSIS_STRUCTURING, true, 10000, 3600, tx_hash, 0xdead, 0, 1099511627776);
}

#[test(should_fail_with = "Transaction after proof timestamp")]
fn test_main_revert_transaction_after_proof_timestamp() {
    let amounts: [u64; 16] = [500, 1200, 3000, 7500, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 4, ANALYSIS_STRUCTURING, true, 10000, 3600, tx_hash, 0xdead, 0, 1700002999);
}

#[test(should_fail_with = "Transaction outside time window")]
fn test_main_revert_transaction_outside_time_window() {
    let amounts: [u64; 16] = [500, 1200, 3000, 7500, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    // Oldest transaction is 3601s before the proof timestamp; window is 3600s.
    run(amounts, timestamps, 4, ANALYSIS_STRUCTURING, true, 10000, 3600, tx_hash, 0xdead, 0, 1700003601);
}

#[test]
fn test_main_transaction_at_proof_timestamp() {
    // Pins the `timestamps[i] <= proof_ts` boundary: a transaction at exactly the proof time is inside.
    let amounts: [u64; 16] = [500, 1200, 3000, 7500, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    run(amounts, timestamps, 4, ANALYSIS_STRUCTURING, true, 10000, 3600, tx_hash, 0xdead, 0, 1700003000);
}

/// Analysis-test call shape: unbound use (seed 0, zero salts), jurisdiction 0,
/// aggregate flag computed from the amounts. `_unbound_root` keeps the pre-XIP-1
/// argument order; the root is derived.
fn run(
    amounts: [u64; 16],
    timestamps: [u64; 16],
    num_transactions: u32,
    analysis_type: u8,
    result: bool,
    reporting_threshold: u64,
    time_window: u64,
    tx_set_hash: Field,
    submitter: Field,
    _unbound_root: Field,
    timestamp: Field,
) {
    let salts: [Field; 16] = [0; 16];
    let root = fold_settlement_root(0, amounts, timestamps, salts, num_transactions);
    let mut sum: u128 = 0;
    for i in 0..16 {
        sum += amounts[i] as u128;
    }
    let aggregate_reportable = sum >= reporting_threshold as u128;
    main(
        amounts,
        timestamps,
        salts,
        num_transactions,
        analysis_type,
        result,
        reporting_threshold,
        time_window,
        tx_set_hash,
        submitter,
        root,
        timestamp,
        0,
        0,
        aggregate_reportable,
    );
}
