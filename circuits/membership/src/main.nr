/// Membership proof circuit
///
/// Proves that the SUBMITTER is a member of an authorized set, without revealing
/// which set position they occupy or any other tree contents. The leaf is computed
/// as `leaf_hash_subject(submitter, set_id, subject_salt)`; the prover supplies the
/// Merkle path to the public root.
///
/// Tree publishers MUST construct each leaf as `leaf_hash_subject(member_address,
/// set_id, salt_for_that_member)` and publish each user's `subject_salt` to that
/// user as part of issuance. Use `subject_salt = 0` when the tree contents are
/// public (e.g. a published whitelist).
///
/// Use cases:
/// - Whitelist verification (KYC-approved addresses)
/// - Authorized counterparty checks
/// - Approved token/pool inclusion
///
/// Public inputs:
///   - merkle_root: root of the membership set tree
///   - set_id: identifier for which set is being checked (e.g., whitelist version)
///   - timestamp: block timestamp for temporal binding
///   - is_member: boolean result
///   - submitter: address of the authorized proof submitter; oracle enforces
///                that this equals msg.sender, and the leaf binding ensures the
///                proof is meaningful FOR THAT SUBMITTER (audit finding H-3).
///
/// Private inputs:
///   - subject_salt: per-user salt provided by the tree publisher (0 if public set)
///   - merkle_index: leaf position in the tree
///   - merkle_path: sibling hashes along the path to root

use erc8262_shared::{compute_merkle_root, internal_hash, leaf_hash_subject, validate_timestamp};

fn main(
    // --- Private ---
    subject_salt: Field,               // per-user salt (0 for public sets)
    merkle_index: Field,               // leaf position in the tree
    merkle_path: [Field; 20],          // MERKLE_DEPTH = 20

    // --- Public ---
    merkle_root: pub Field,            // root of the authorized set
    set_id: pub Field,                 // identifies which set (versioning)
    timestamp: pub Field,              // temporal binding
    is_member: pub bool,               // the result
    submitter: pub Field,              // authorized submitter address (oracle enforces == msg.sender)
) {
    // 1. Compute the leaf hash binding the submitter to the set.
    //    leaf = H(DOMAIN_LEAF_SUBJECT, submitter, set_id, subject_salt)
    let leaf = leaf_hash_subject(submitter, set_id, subject_salt);

    // 2. Compute the Merkle root from the leaf and path
    let computed_root = compute_merkle_root(leaf, merkle_index, merkle_path);

    // 3. Verify membership: computed root must match the public root
    let membership_valid = computed_root == merkle_root;
    assert(membership_valid == is_member, "Membership result mismatch");

    // 4. Timestamp must be within reasonable bounds
    validate_timestamp(timestamp);

    // 5. Submitter must be non-zero (also enforced by the oracle)
    assert(submitter != 0, "submitter must be non-zero");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Build a simple 2-level Merkle tree for testing
/// Tree:        root
///            /      \
///         h01        h23
///        /   \      /   \
///      leaf0 leaf1 leaf2 leaf3
///
/// For MERKLE_DEPTH=20, we pad remaining levels with zero siblings.

#[test]
fn test_membership_valid() {
    // Submitter is a member of set 1, with public salt=0
    let submitter: Field = 0xabcd;
    let set_id: Field = 1;
    let salt: Field = 0;
    let leaf = leaf_hash_subject(submitter, set_id, salt);

    // Build a trivial path: all siblings are zero (leaf is at index 0)
    let path: [Field; 20] = [0; 20];

    // Compute expected root using internal_hash (matches compute_merkle_root)
    let mut current = leaf;
    for _i in 0..20 {
        current = internal_hash(current, 0);
    }
    let expected_root = current;

    let computed = compute_merkle_root(leaf, 0, path);
    assert(computed == expected_root);
}

#[test]
fn test_leaf_bound_to_submitter() {
    // Different submitters produce different leaves under the same set + salt
    let set_id: Field = 1;
    let salt: Field = 0;
    let leaf_alice = leaf_hash_subject(0xa, set_id, salt);
    let leaf_bob = leaf_hash_subject(0xb, set_id, salt);
    assert(leaf_alice != leaf_bob);
}

#[test]
fn test_leaf_bound_to_set_id() {
    // Same submitter in different sets produces different leaves
    let submitter: Field = 0xabcd;
    let salt: Field = 0;
    let leaf_set1 = leaf_hash_subject(submitter, 1, salt);
    let leaf_set2 = leaf_hash_subject(submitter, 2, salt);
    assert(leaf_set1 != leaf_set2);
}

#[test]
fn test_leaf_bound_to_salt() {
    // Same submitter in same set with different salts produces different leaves
    let submitter: Field = 0xabcd;
    let set_id: Field = 1;
    let leaf_salt0 = leaf_hash_subject(submitter, set_id, 0);
    let leaf_salt1 = leaf_hash_subject(submitter, set_id, 0xdeadbeef);
    assert(leaf_salt0 != leaf_salt1);
}

#[test]
fn test_main_valid_membership_public_set() {
    // Public-set membership (salt=0). Submitter 0xabcd is a member.
    let submitter: Field = 0xabcd;
    let set_id: Field = 1;
    let salt: Field = 0;
    let leaf = leaf_hash_subject(submitter, set_id, salt);

    let path: [Field; 20] = [0; 20];
    let root = compute_merkle_root(leaf, 0, path);

    main(salt, 0, path, root, set_id, 1700000000, true, submitter);
}

#[test]
fn test_main_valid_membership_private_set() {
    // Private-set membership with a non-zero salt
    let submitter: Field = 0xfeed;
    let set_id: Field = 7;
    let salt: Field = 0xbadcafe;
    let leaf = leaf_hash_subject(submitter, set_id, salt);

    let path: [Field; 20] = [0; 20];
    let root = compute_merkle_root(leaf, 0, path);

    main(salt, 0, path, root, set_id, 1700000000, true, submitter);
}

#[test]
fn test_main_invalid_membership() {
    // Submitter 0xabcd is in the tree, but 0xdead is the prover -> not a member
    let real_submitter: Field = 0xabcd;
    let fake_submitter: Field = 0xdead;
    let set_id: Field = 1;
    let salt: Field = 0;
    let real_leaf = leaf_hash_subject(real_submitter, set_id, salt);

    let path: [Field; 20] = [0; 20];
    let root = compute_merkle_root(real_leaf, 0, path);

    // Prover is fake_submitter; their leaf hashes to a different value, so root mismatch
    main(salt, 0, path, root, set_id, 1700000000, false, fake_submitter);
}
