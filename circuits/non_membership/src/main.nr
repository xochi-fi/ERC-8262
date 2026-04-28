/// Non-membership proof circuit
///
/// Proves the SUBMITTER's address is NOT in a sorted set (e.g. a sanctions list)
/// without revealing other tree contents. The tree is constructed by the publisher
/// as a sorted-by-value Merkle tree of leaves
///   leaf_i = leaf_hash_subject(value_i, set_id, salt_i)
/// where `value_i` are the included addresses (raw Field representation) sorted in
/// ascending order. The publisher MUST insert sentinel boundary leaves at value=0
/// and value=p-1 (BN254 prime minus 1) to ensure every submitter has well-defined
/// neighbors.
///
/// Non-membership is proven by showing two **adjacent** leaves (low, high) such that:
///   low_value < submitter < high_value
///   high_index == low_index + 1
/// and both leaves verify against the tree. The adjacency requirement closes a
/// soundness gap in the previous design where an attacker could pick non-adjacent
/// brackets and skip a real tree entry between them.
///
/// Comparison is performed on full BN254 Field elements via `Field.lt()`, which
/// uses bit-decomposition (audit finding M-2). The previous u64 ceiling has been
/// removed; Ethereum addresses (160-bit) and arbitrary-width identifiers all fit
/// in Field and compare correctly.
///
/// Public inputs:
///   - merkle_root: root of the sorted set tree
///   - set_id: identifier for which set (e.g. OFAC list version)
///   - timestamp: block timestamp for temporal binding
///   - is_non_member: boolean result (true = submitter is NOT in the set)
///   - submitter: address of the authorized proof submitter (audit finding H-3:
///                this is the value being proven non-member; oracle enforces
///                submitter == msg.sender)
///
/// Private inputs:
///   - low_leaf:        the largest value in the tree less than submitter
///   - low_leaf_salt:   salt used for low_leaf in the tree (0 for public sets)
///   - low_index:       Merkle index of low_leaf
///   - low_path:        Merkle path for low_leaf
///   - high_leaf:       the smallest value in the tree greater than submitter
///   - high_leaf_salt:  salt used for high_leaf
///   - high_index:      Merkle index of high_leaf (must equal low_index + 1)
///   - high_path:       Merkle path for high_leaf

use xochi_shared::{compute_merkle_root, leaf_hash_subject, validate_timestamp};

fn main(
    // --- Private ---
    low_leaf: Field,
    low_leaf_salt: Field,
    low_index: Field,
    low_path: [Field; 20],
    high_leaf: Field,
    high_leaf_salt: Field,
    high_index: Field,
    high_path: [Field; 20],

    // --- Public ---
    merkle_root: pub Field,
    set_id: pub Field,
    timestamp: pub Field,
    is_non_member: pub bool,
    submitter: pub Field,
) {
    // 1. Submitter must be non-zero (also enforced by oracle)
    assert(submitter != 0, "submitter must be non-zero");

    // 2. Timestamp must be within reasonable bounds
    validate_timestamp(timestamp);

    // 3. Compute leaf hashes (binding to set_id and per-leaf salt). Same domain tag
    //    as membership ensures the same tree format may be used for both proof types.
    let low_leaf_hash = leaf_hash_subject(low_leaf, set_id, low_leaf_salt);
    let high_leaf_hash = leaf_hash_subject(high_leaf, set_id, high_leaf_salt);

    // 4. Field-element ordering: low_leaf < submitter < high_leaf.
    //    Field.lt() uses bit-decomposition over the full Field range; no u64
    //    truncation, no MAX_ELEMENT_VALUE ceiling.
    let ordering_valid = low_leaf.lt(submitter) & submitter.lt(high_leaf);

    // 5. Both leaves must be in the tree
    let low_root = compute_merkle_root(low_leaf_hash, low_index, low_path);
    let low_valid = low_root == merkle_root;
    let high_root = compute_merkle_root(high_leaf_hash, high_index, high_path);
    let high_valid = high_root == merkle_root;

    // 6. Adjacency: high_index == low_index + 1. Without this check, an attacker
    //    could pick low/high that bracket the submitter but are not adjacent in the
    //    tree, leaving a hidden middle entry that IS the submitter. (Soundness gap
    //    in the previous version; tree publisher MUST sort leaves by value.)
    let adjacent = high_index == low_index + 1;

    // 7. Non-membership = ordering AND inclusion AND adjacency
    let computed_non_member = ordering_valid & low_valid & high_valid & adjacent;
    assert(computed_non_member == is_non_member, "Non-membership result mismatch");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Build a 2-leaf tree (low at index 0, high at index 1) and return (root, paths).
fn build_two_leaf_tree(low_leaf_hash: Field, high_leaf_hash: Field) -> (Field, [Field; 20], [Field; 20]) {
    let mut low_path: [Field; 20] = [0; 20];
    low_path[0] = high_leaf_hash;
    let mut high_path: [Field; 20] = [0; 20];
    high_path[0] = low_leaf_hash;
    let root = compute_merkle_root(low_leaf_hash, 0, low_path);
    (root, low_path, high_path)
}

#[test]
fn test_field_lt_basic() {
    let a: Field = 10;
    let b: Field = 50;
    let c: Field = 100;
    assert(a.lt(b) & b.lt(c));
    assert(!a.lt(a));
    assert(!c.lt(a));
}

#[test]
fn test_field_lt_full_field_range() {
    // Comparison works correctly for values larger than u64::MAX (this is the M-2 fix)
    let huge: Field = 0x1000000000000000000; // 2^72, doesn't fit in u64
    let bigger: Field = 0x2000000000000000000; // 2^73
    assert(huge.lt(bigger));
}

#[test]
fn test_main_valid_non_membership() {
    // Prove submitter=50 is not in a set containing {10, 100}
    let submitter: Field = 50;
    let low_leaf: Field = 10;
    let high_leaf: Field = 100;
    let set_id: Field = 1;

    let low_leaf_hash = leaf_hash_subject(low_leaf, set_id, 0);
    let high_leaf_hash = leaf_hash_subject(high_leaf, set_id, 0);
    let (root, low_path, high_path) = build_two_leaf_tree(low_leaf_hash, high_leaf_hash);

    main(
        low_leaf, 0, 0, low_path,
        high_leaf, 0, 1, high_path,
        root, set_id, 1700000000, true, submitter,
    );
}

#[test]
fn test_main_valid_non_membership_with_salts() {
    // Per-leaf salts (tree privacy) still produce valid proofs
    let submitter: Field = 0x1500;
    let low_leaf: Field = 0x1000;
    let high_leaf: Field = 0x2000;
    let set_id: Field = 1;
    let low_salt: Field = 0xdeadbeef;
    let high_salt: Field = 0xfeedface;

    let low_leaf_hash = leaf_hash_subject(low_leaf, set_id, low_salt);
    let high_leaf_hash = leaf_hash_subject(high_leaf, set_id, high_salt);
    let (root, low_path, high_path) = build_two_leaf_tree(low_leaf_hash, high_leaf_hash);

    main(
        low_leaf, low_salt, 0, low_path,
        high_leaf, high_salt, 1, high_path,
        root, set_id, 1700000000, true, submitter,
    );
}

#[test]
fn test_main_above_u64_range() {
    // Submitter and tree leaves all exceed 2^64; the old design rejected this, the new
    // design accepts it because Field.lt() works over the full Field range (M-2 fix).
    let submitter: Field = 0x10000000000000000; // 2^64
    let low_leaf: Field = 0xffffffffffffffff;   // 2^64 - 1
    let high_leaf: Field = 0x100000000000000ff; // 2^64 + 0xff
    let set_id: Field = 1;

    let low_leaf_hash = leaf_hash_subject(low_leaf, set_id, 0);
    let high_leaf_hash = leaf_hash_subject(high_leaf, set_id, 0);
    let (root, low_path, high_path) = build_two_leaf_tree(low_leaf_hash, high_leaf_hash);

    main(
        low_leaf, 0, 0, low_path,
        high_leaf, 0, 1, high_path,
        root, set_id, 1700000000, true, submitter,
    );
}

#[test(should_fail_with = "Non-membership result mismatch")]
fn test_main_revert_submitter_equals_low_leaf() {
    let submitter: Field = 50;
    let low_leaf: Field = 50;
    let high_leaf: Field = 100;
    let set_id: Field = 1;
    let low_leaf_hash = leaf_hash_subject(low_leaf, set_id, 0);
    let high_leaf_hash = leaf_hash_subject(high_leaf, set_id, 0);
    let (root, low_path, high_path) = build_two_leaf_tree(low_leaf_hash, high_leaf_hash);

    main(
        low_leaf, 0, 0, low_path,
        high_leaf, 0, 1, high_path,
        root, set_id, 1700000000, true, submitter,
    );
}

#[test(should_fail_with = "Non-membership result mismatch")]
fn test_main_revert_submitter_equals_high_leaf() {
    let submitter: Field = 100;
    let low_leaf: Field = 50;
    let high_leaf: Field = 100;
    let set_id: Field = 1;
    let low_leaf_hash = leaf_hash_subject(low_leaf, set_id, 0);
    let high_leaf_hash = leaf_hash_subject(high_leaf, set_id, 0);
    let (root, low_path, high_path) = build_two_leaf_tree(low_leaf_hash, high_leaf_hash);

    main(
        low_leaf, 0, 0, low_path,
        high_leaf, 0, 1, high_path,
        root, set_id, 1700000000, true, submitter,
    );
}

#[test(should_fail_with = "Non-membership result mismatch")]
fn test_main_revert_non_adjacent_brackets() {
    // Soundness gap fix: low_index=0, high_index=2 (not adjacent). Even though both
    // are in the tree and bracket the submitter, the proof is rejected because the
    // attacker could be hiding a real entry at index 1 between them.
    //
    // Build a 4-leaf tree with leaves at indices 0,1,2: hashes h0, h1, h2 (h3 is zero).
    // submitter is between h0's value and h2's value. The (real) entry at index 1
    // between them is the missing tree member; this attack would succeed if not for
    // the adjacency check.
    let submitter: Field = 50;
    let low_leaf: Field = 10;
    let mid_leaf: Field = 30;  // exists at index 1 -- the entry the attacker is "hiding"
    let high_leaf: Field = 100;
    let set_id: Field = 1;

    let h0 = leaf_hash_subject(low_leaf, set_id, 0);
    let h1 = leaf_hash_subject(mid_leaf, set_id, 0);
    let h2 = leaf_hash_subject(high_leaf, set_id, 0);
    let h3: Field = 0;

    // Build 4-leaf tree manually
    let h01 = xochi_shared::internal_hash(h0, h1);
    let h23 = xochi_shared::internal_hash(h2, h3);
    let root_2levels = xochi_shared::internal_hash(h01, h23);
    // Pad to depth 20
    let mut current = root_2levels;
    for _i in 2..20 {
        current = xochi_shared::internal_hash(current, 0);
    }
    let root = current;

    // Path for index 0: [h1, h23, 0, 0, ...]
    let mut low_path: [Field; 20] = [0; 20];
    low_path[0] = h1;
    low_path[1] = h23;

    // Path for index 2: [h3, h01, 0, 0, ...]
    let mut high_path: [Field; 20] = [0; 20];
    high_path[0] = h3;
    high_path[1] = h01;

    // Attacker uses indices 0 and 2 (skipping index 1 where mid_leaf is).
    main(
        low_leaf, 0, 0, low_path,
        high_leaf, 0, 2, high_path,
        root, set_id, 1700000000, true, submitter,
    );
}
