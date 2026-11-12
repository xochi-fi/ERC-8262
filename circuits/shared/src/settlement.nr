/// Settlement-leg binding (XIP-1).
///
/// A split settlement is a hash chain over its legs:
///
///   root_0     = settlement_seed            (registry-derived, binds tradeId/subject/n)
///   root_{i+1} = settlement_link(root_i, amount_i, timestamp_i, salt_i)
///
/// Each leg's compliance proof extends the chain by one link and exposes
/// (link_in, link_out) publicly; the registry accepts a leg only if link_in
/// equals its stored root, then stores link_out. The pattern circuit refolds the
/// chain from the public seed over the transactions it analyses and asserts the
/// result equals the public settlement_root, so it can only analyse exactly the
/// recorded legs, in order, with the committed amounts and timestamps.
///
/// Hash: one Poseidon2 (t=4) permutation per link, domain tag in the capacity
/// element. Inputs are packed injectively: amount * 2^40 + timestamp, with
/// timestamp < 2^40.

/// Domain tag for chain links ("XIP1.link"), placed in the capacity element
/// alongside the absorbed length so no other Poseidon2 use can produce a link.
global DOMAIN_SETTLEMENT_LINK: Field = 0x584950312e6c696e6b * 0x10000000000000000 + 3;

global TWO_POW_40: Field = 0x10000000000;

/// One link of the settlement chain.
pub fn settlement_link(prev: Field, amount: u64, timestamp: u64, salt: Field) -> Field {
    assert(timestamp < 1099511627776, "Leg timestamp exceeds 2^40");
    let packed = (amount as Field) * TWO_POW_40 + (timestamp as Field);
    std::hash::poseidon2_permutation([prev, packed, salt, DOMAIN_SETTLEMENT_LINK])[0]
}

/// Fold the first `n` legs onto `seed`.
pub fn fold_settlement_root<let N: u32>(
    seed: Field,
    amounts: [u64; N],
    timestamps: [u64; N],
    salts: [Field; N],
    n: u32,
) -> Field {
    let mut root = seed;
    for i in 0..N {
        if (i as u32) < n {
            root = settlement_link(root, amounts[i], timestamps[i], salts[i]);
        }
    }
    root
}

#[test]
fn test_link_is_order_sensitive() {
    let a = settlement_link(settlement_link(7, 100, 1700000000, 1), 200, 1700000001, 2);
    let b = settlement_link(settlement_link(7, 200, 1700000001, 2), 100, 1700000000, 1);
    assert(a != b);
}

#[test]
fn test_link_separates_amount_and_timestamp() {
    // amount and timestamp cannot trade bits: (1, 0) vs (0, 2^40) is out of range.
    assert(settlement_link(0, 1, 0, 0) != settlement_link(0, 0, 1, 0));
}

#[test(should_fail_with = "Leg timestamp exceeds 2^40")]
fn test_link_rejects_wide_timestamp() {
    let _ = settlement_link(0, 0, 1099511627776, 0);
}

#[test]
fn test_fold_matches_manual_chain() {
    let amounts: [u64; 4] = [5, 6, 0, 0];
    let timestamps: [u64; 4] = [1700000000, 1700000100, 0, 0];
    let salts: [Field; 4] = [11, 12, 0, 0];
    let manual = settlement_link(settlement_link(9, 5, 1700000000, 11), 6, 1700000100, 12);
    assert(fold_settlement_root(9, amounts, timestamps, salts, 2) == manual);
}
