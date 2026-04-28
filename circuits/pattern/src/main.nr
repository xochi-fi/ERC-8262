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
///   - reporting_threshold: the jurisdiction's reporting threshold (in basis points)
///   - time_window: the analysis window in seconds
///   - tx_set_hash: commitment to the transaction set analyzed
///   - submitter: address of the authorized proof submitter (anti-frontrun)
///
/// Private inputs:
///   - amounts: transaction amounts
///   - timestamps: transaction timestamps
///   - num_transactions: how many are active

use xochi_shared::{MAX_TRANSACTIONS, compute_tx_set_hash, validate_timestamp};

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

/// Maximum reporting threshold to prevent u64 overflow in floor calculation.
/// floor = threshold * 90 / 100, so threshold must be < 2^64 / 90.
global MAX_REPORTING_THRESHOLD: u64 = 204962515653461695;

fn main(
    // --- Private ---
    amounts: [u64; 16],
    timestamps: [u64; 16],
    num_transactions: u32,

    // --- Public ---
    analysis_type: pub u8,
    result: pub bool,              // true = clean (no structuring)
    reporting_threshold: pub u64,  // jurisdiction reporting threshold
    time_window: pub u64,          // analysis window in seconds
    tx_set_hash: pub Field,        // commitment to the analyzed set
    submitter: pub Field,           // authorized submitter address (oracle enforces == msg.sender)
) {
    // Validate inputs
    assert(num_transactions >= 1, "At least one transaction required");
    assert(num_transactions <= MAX_TRANSACTIONS, "Too many transactions");
    assert(reporting_threshold > 0, "Threshold must be positive");
    assert(
        reporting_threshold <= MAX_REPORTING_THRESHOLD,
        "Threshold too large, would overflow",
    );
    assert(time_window > 0, "Time window must be positive");

    // Anchor submitter as a public input (oracle enforces submitter == msg.sender).
    assert(submitter != 0, "submitter must be non-zero");

    // Validate active slots have sane timestamps; ensure inactive slots are zeroed
    for i in 0..16 {
        if (i as u32) < num_transactions {
            validate_timestamp(timestamps[i] as Field);
        } else {
            assert(amounts[i] == 0, "Inactive amount must be zero");
            assert(timestamps[i] == 0, "Inactive timestamp must be zero");
        }
    }

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

/// Check velocity: ensure not too many transactions in the time window
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

    main(amounts, timestamps, 4, ANALYSIS_STRUCTURING, true, 10000, 3600, tx_hash, 0xdead);
}

#[test]
fn test_main_velocity_clean() {
    let amounts: [u64; 16] = [100, 200, 300, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700000500, 1700001000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    main(amounts, timestamps, 3, ANALYSIS_VELOCITY, true, 10000, 3600, tx_hash, 0xdead);
}

#[test]
fn test_main_round_amounts_clean() {
    let amounts: [u64; 16] = [1234, 5678, 3000, 9876, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    main(amounts, timestamps, 4, ANALYSIS_ROUND_AMOUNT, true, 10000, 3600, tx_hash, 0xdead);
}

#[test]
fn test_main_structuring_detected() {
    // 3 of 4 amounts in [9000, 10000) -> structuring detected
    let amounts: [u64; 16] = [9500, 9800, 9200, 500, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    main(amounts, timestamps, 4, ANALYSIS_STRUCTURING, false, 10000, 3600, tx_hash, 0xdead);
}

#[test]
fn test_structuring_threshold_boundary() {
    // amounts == threshold, NOT < threshold, so not in suspicious range
    let amounts: [u64; 16] = [10000, 10000, 10000, 10000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    main(amounts, timestamps, 4, ANALYSIS_STRUCTURING, true, 10000, 3600, tx_hash, 0xdead);
}

#[test]
fn test_velocity_exactly_max() {
    let amounts: [u64; 16] = [100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700000100, 1700000200, 1700000300, 1700000400, 1700000500, 1700000600, 1700000700, 1700000800, 1700000900, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    main(amounts, timestamps, 10, ANALYSIS_VELOCITY, true, 10000, 3600, tx_hash, 0xdead);
}

#[test]
fn test_velocity_exceeds_max() {
    let amounts: [u64; 16] = [100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700000100, 1700000200, 1700000300, 1700000400, 1700000500, 1700000600, 1700000700, 1700000800, 1700000900, 1700001000, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    main(amounts, timestamps, 11, ANALYSIS_VELOCITY, false, 10000, 3600, tx_hash, 0xdead);
}

#[test]
fn test_round_amounts_all_round() {
    // 4/4 round amounts -> round_count*100=400, num*80=320, 400 < 320 is false -> not clean
    let amounts: [u64; 16] = [1000, 2000, 3000, 4000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 1700001000, 1700002000, 1700003000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    main(amounts, timestamps, 4, ANALYSIS_ROUND_AMOUNT, false, 10000, 3600, tx_hash, 0xdead);
}

#[test]
fn test_structuring_max_threshold_single_tx() {
    // Single transaction at MAX_REPORTING_THRESHOLD with amount well below floor.
    // floor = 204962515653461695 * 90 / 100 = 184466264088115525
    // amount 100 < floor -> not suspicious -> clean
    let amounts: [u64; 16] = [100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    main(amounts, timestamps, 1, ANALYSIS_STRUCTURING, true, MAX_REPORTING_THRESHOLD, 3600, tx_hash, 0xdead);
}

#[test]
fn test_structuring_max_threshold_single_tx_suspicious() {
    // Single transaction with amount at the floor value (suspicious range).
    // floor = 204962515653461695 * 90 / 100 = 184466264088115525
    // amount == floor -> in [floor, threshold) -> suspicious
    // 1 suspicious out of 1 total: half = (1+1)/2 = 1, suspicious_count(1) < 1 is false -> not clean
    let amounts: [u64; 16] = [184466264088115525, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let timestamps: [u64; 16] = [1700000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let tx_hash = compute_tx_set_hash(amounts, timestamps);

    main(amounts, timestamps, 1, ANALYSIS_STRUCTURING, false, MAX_REPORTING_THRESHOLD, 3600, tx_hash, 0xdead);
}
