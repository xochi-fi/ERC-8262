/// Attestation circuit (credential/tier verification) -- redesigned per audit C-1.
///
/// Proves that the SUBMITTER holds a credential that was issued to them by a specific
/// provider, without revealing the credential's private attributes. Use cases:
/// - KYC tier verification
/// - Accredited investor status
/// - Institutional qualification
///
/// Trust model
/// -----------
/// Each provider maintains a per-provider Merkle tree of issued credentials. The
/// provider publishes the latest tree root on-chain via ERC8262Oracle.publishCredentialRoot
/// (callable only by the provider's authorized publisher EOA, registered by the
/// oracle owner). The on-chain registry binds each root to its providerId; the
/// Solidity validator checks that the proof's claimed provider_id matches the
/// providerId stored against the credential_root.
///
/// Each leaf in the credentials tree is `leaf_hash_value(credential_hash)`, where
/// credential_hash = H(DOMAIN_CREDENTIAL, provider_id, submitter, credential_type,
///                     credential_attribute, expiry_timestamp)
/// This hash binds the credential to a SPECIFIC submitter at issuance time, so
/// only that submitter can produce a valid proof (closes audit findings C-1 and H-3).
/// Forging a credential requires producing a Merkle path to a leaf in the registered
/// tree, which only the provider can authorize by publishing a new root.
///
/// Public inputs:
///   - provider_id: which provider issued the credential (must match registry)
///   - credential_type: what kind of credential (KYC_BASIC=1, ..., INSTITUTIONAL=4)
///   - is_valid: boolean result (= not_expired AND valid_type, given inclusion)
///   - credential_root: root of the provider's credentials tree
///   - current_timestamp: for expiry checking (oracle bounds via MAX_PROOF_AGE)
///   - submitter: prover address; oracle enforces submitter == msg.sender
///
/// Private inputs:
///   - credential_attribute: opaque per-credential attribute value (e.g. KYC level)
///   - expiry_timestamp: when the credential expires
///   - merkle_index: position of this credential in the tree
///   - merkle_path: Merkle path to the credential_root

use std::hash::pedersen_hash;
use erc8262_shared::{compute_merkle_root, leaf_hash_value};

/// Credential types (2 and 3 are reserved for future use, e.g. KYC Enhanced, Accredited Investor)
global CREDENTIAL_KYC_BASIC: u8 = 1;
global CREDENTIAL_INSTITUTIONAL: u8 = 4;

/// Domain tag for credential hashes; distinct from any merkle leaf domain.
global DOMAIN_CREDENTIAL: Field = 0x435245445f48; // ASCII "CRED_H"

fn main(
    // --- Private ---
    credential_attribute: Field,
    expiry_timestamp: u64,
    merkle_index: Field,
    merkle_path: [Field; 20],

    // --- Public ---
    provider_id: pub Field,
    credential_type: pub u8,
    is_valid: pub bool,
    credential_root: pub Field,
    current_timestamp: pub u64,
    submitter: pub Field,
) {
    // 1. Submitter must be non-zero (oracle enforces == msg.sender)
    assert(submitter != 0, "submitter must be non-zero");

    // 2. Compute the credential hash, binding (provider_id, submitter, type, attr, expiry)
    let credential_hash = compute_credential_hash(
        provider_id,
        submitter,
        credential_type,
        credential_attribute,
        expiry_timestamp,
    );

    // 3. The leaf is leaf_hash_value(credential_hash); verify it is in the credentials tree
    let leaf = leaf_hash_value(credential_hash);
    let computed_root = compute_merkle_root(leaf, merkle_index, merkle_path);
    assert(computed_root == credential_root, "Credential not in tree");

    // 4. Check credential expiry
    let not_expired = current_timestamp < expiry_timestamp;

    // 5. Validate credential type
    let valid_type =
        (credential_type >= CREDENTIAL_KYC_BASIC) & (credential_type <= CREDENTIAL_INSTITUTIONAL);

    // 6. is_valid result -- inclusion already enforced via assert above; here we
    //    encode the additional checks for the public-output boolean.
    let computed_valid = not_expired & valid_type;
    assert(computed_valid == is_valid, "Validity result mismatch");
}

/// Compute the credential hash that binds all credential components.
/// The provider commits to this hash by including leaf_hash_value(credential_hash)
/// in their published Merkle tree.
fn compute_credential_hash(
    provider_id: Field,
    submitter: Field,
    credential_type: u8,
    attribute: Field,
    expiry: u64,
) -> Field {
    pedersen_hash([
        DOMAIN_CREDENTIAL,
        provider_id,
        submitter,
        credential_type as Field,
        attribute,
        expiry as Field,
    ])
}

/// Build a single-leaf credentials tree at index 0 and return its root + path.
fn build_singleton_tree(credential_hash: Field) -> (Field, [Field; 20]) {
    let path: [Field; 20] = [0; 20];
    let leaf = leaf_hash_value(credential_hash);
    let root = compute_merkle_root(leaf, 0, path);
    (root, path)
}

#[test]
fn test_credential_hash_deterministic() {
    let h1 = compute_credential_hash(1, 2, CREDENTIAL_KYC_BASIC, 3, 1000);
    let h2 = compute_credential_hash(1, 2, CREDENTIAL_KYC_BASIC, 3, 1000);
    assert(h1 == h2);
}

#[test]
fn test_credential_hash_bound_to_submitter() {
    // Same credential issued to two different submitters produces different hashes
    let h_alice = compute_credential_hash(42, 0xa, CREDENTIAL_KYC_BASIC, 999, 2000000000);
    let h_bob = compute_credential_hash(42, 0xb, CREDENTIAL_KYC_BASIC, 999, 2000000000);
    assert(h_alice != h_bob);
}

#[test]
fn test_credential_hash_bound_to_provider() {
    let h_p1 = compute_credential_hash(42, 0xa, CREDENTIAL_KYC_BASIC, 999, 2000000000);
    let h_p2 = compute_credential_hash(99, 0xa, CREDENTIAL_KYC_BASIC, 999, 2000000000);
    assert(h_p1 != h_p2);
}

#[test]
fn test_main_valid_credential() {
    let provider_id: Field = 42;
    let submitter: Field = 0xdead;
    let cred_type: u8 = CREDENTIAL_KYC_BASIC;
    let attribute: Field = 999;
    let expiry: u64 = 2000000000;
    let current: u64 = 1700000000;

    let credential_hash =
        compute_credential_hash(provider_id, submitter, cred_type, attribute, expiry);
    let (root, path) = build_singleton_tree(credential_hash);

    main(attribute, expiry, 0, path, provider_id, cred_type, true, root, current, submitter);
}

#[test]
fn test_main_expired_credential() {
    let provider_id: Field = 42;
    let submitter: Field = 0xdead;
    let cred_type: u8 = CREDENTIAL_KYC_BASIC;
    let attribute: Field = 999;
    let expiry: u64 = 1600000000;
    let current: u64 = 1700000000;

    let credential_hash =
        compute_credential_hash(provider_id, submitter, cred_type, attribute, expiry);
    let (root, path) = build_singleton_tree(credential_hash);

    main(attribute, expiry, 0, path, provider_id, cred_type, false, root, current, submitter);
}

#[test(should_fail_with = "Credential not in tree")]
fn test_main_revert_credential_not_in_tree() {
    // Forgery attempt: prover invents a credential with no Merkle path to a registered root.
    let provider_id: Field = 42;
    let submitter: Field = 0xdead;
    let cred_type: u8 = CREDENTIAL_KYC_BASIC;
    let attribute: Field = 999;
    let expiry: u64 = 2000000000;
    let current: u64 = 1700000000;

    // Build a tree containing a DIFFERENT credential
    let real_credential_hash =
        compute_credential_hash(provider_id, submitter, cred_type, 1234, expiry);
    let (root, path) = build_singleton_tree(real_credential_hash);

    // Try to prove a credential with `attribute=999` (different from the one in the tree)
    main(attribute, expiry, 0, path, provider_id, cred_type, true, root, current, submitter);
}

#[test(should_fail_with = "Credential not in tree")]
fn test_main_revert_wrong_submitter() {
    // C-1 / H-3: a credential issued to alice cannot be proved by bob.
    let provider_id: Field = 42;
    let alice: Field = 0xa11ce;
    let bob: Field = 0xb0b;
    let cred_type: u8 = CREDENTIAL_KYC_BASIC;
    let attribute: Field = 999;
    let expiry: u64 = 2000000000;
    let current: u64 = 1700000000;

    // Provider issued the credential to alice
    let alice_credential_hash =
        compute_credential_hash(provider_id, alice, cred_type, attribute, expiry);
    let (root, path) = build_singleton_tree(alice_credential_hash);

    // Bob tries to prove with submitter=bob -- credential_hash recomputed under bob != stored leaf
    main(attribute, expiry, 0, path, provider_id, cred_type, true, root, current, bob);
}

#[test]
fn test_main_credential_type_zero_invalid() {
    // credential_type=0 is out of valid range, but if the tree happens to contain a
    // credential with type=0, the proof verifies inclusion but `is_valid` must be false.
    let provider_id: Field = 42;
    let submitter: Field = 0xdead;
    let cred_type: u8 = 0;
    let attribute: Field = 999;
    let expiry: u64 = 2000000000;
    let current: u64 = 1700000000;

    let credential_hash =
        compute_credential_hash(provider_id, submitter, cred_type, attribute, expiry);
    let (root, path) = build_singleton_tree(credential_hash);

    main(attribute, expiry, 0, path, provider_id, cred_type, false, root, current, submitter);
}

#[test]
fn test_main_credential_type_above_max_invalid() {
    let provider_id: Field = 42;
    let submitter: Field = 0xdead;
    let cred_type: u8 = 5;
    let attribute: Field = 999;
    let expiry: u64 = 2000000000;
    let current: u64 = 1700000000;

    let credential_hash =
        compute_credential_hash(provider_id, submitter, cred_type, attribute, expiry);
    let (root, path) = build_singleton_tree(credential_hash);

    main(attribute, expiry, 0, path, provider_id, cred_type, false, root, current, submitter);
}

#[test]
fn test_main_credential_type_boundary_institutional() {
    let provider_id: Field = 42;
    let submitter: Field = 0xdead;
    let cred_type: u8 = CREDENTIAL_INSTITUTIONAL;
    let attribute: Field = 999;
    let expiry: u64 = 2000000000;
    let current: u64 = 1700000000;

    let credential_hash =
        compute_credential_hash(provider_id, submitter, cred_type, attribute, expiry);
    let (root, path) = build_singleton_tree(credential_hash);

    main(attribute, expiry, 0, path, provider_id, cred_type, true, root, current, submitter);
}

#[test]
fn test_main_expiry_exact_boundary() {
    // current == expiry: not strictly less than, so expired.
    let provider_id: Field = 42;
    let submitter: Field = 0xdead;
    let cred_type: u8 = CREDENTIAL_KYC_BASIC;
    let attribute: Field = 999;
    let expiry: u64 = 1700000000;
    let current: u64 = 1700000000;

    let credential_hash =
        compute_credential_hash(provider_id, submitter, cred_type, attribute, expiry);
    let (root, path) = build_singleton_tree(credential_hash);

    main(attribute, expiry, 0, path, provider_id, cred_type, false, root, current, submitter);
}
