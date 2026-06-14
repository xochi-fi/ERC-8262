#!/usr/bin/env bash
set -euo pipefail

# Generate test fixtures (proof + public_inputs) for each circuit.
# Requires: nargo, bb
#
# Usage: ./scripts/generate-fixtures.sh [circuit_name]
#   If no circuit is specified, generates fixtures for all circuits that
#   have a Prover.toml file.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CIRCUITS_DIR="$REPO_ROOT/circuits"
FIXTURES_DIR="$REPO_ROOT/test/fixtures"

NARGO="${NARGO:-$(command -v nargo 2>/dev/null || echo "$HOME/.nargo/bin/nargo")}"
BB="${BB:-$(command -v bb 2>/dev/null || echo "$HOME/.bb/bb")}"

if [[ ! -x "$NARGO" ]]; then
    echo "error: nargo not found (set NARGO env var)" >&2
    exit 1
fi
if [[ ! -x "$BB" ]]; then
    echo "error: bb not found (set BB env var)" >&2
    exit 1
fi

generate_fixture() {
    local circuit="$1"
    local circuit_dir="$CIRCUITS_DIR/$circuit"

    echo "--- $circuit ---"

    # Compile if needed (nargo 1.0.0-beta.20 writes to workspace target/)
    local circuit_json="$CIRCUITS_DIR/target/$circuit.json"
    if [[ ! -f "$circuit_json" ]]; then
        # Fallback for older nargo versions
        circuit_json="$circuit_dir/target/$circuit.json"
    fi
    if [[ ! -f "$circuit_json" ]]; then
        echo "  compiling..."
        (cd "$circuit_dir" && "$NARGO" compile)
        circuit_json="$CIRCUITS_DIR/target/$circuit.json"
        if [[ ! -f "$circuit_json" ]]; then
            circuit_json="$circuit_dir/target/$circuit.json"
        fi
    fi

    # Verifier-only mode for circuits without Prover.toml.
    # The signed-variant circuits (compliance_signed, risk_score_signed) require an
    # off-chain ECDSA signature over an in-circuit Pedersen digest to populate
    # Prover.toml; until that signing helper lands, we generate the verifier from
    # the VK only and skip proof/fixture generation.
    if [[ ! -f "$circuit_dir/Prover.toml" ]]; then
        echo "  no Prover.toml -- verifier-only mode"
        local vk_dir="$circuit_dir/target/vk"
        rm -r "$vk_dir" 2>/dev/null || true
        mkdir -p "$vk_dir"
        "$BB" write_vk \
            -b "$circuit_json" \
            -t evm \
            -o "$vk_dir"
        echo "  generating solidity verifier..."
        "$BB" write_solidity_verifier \
            -k "$vk_dir/vk" \
            -o "$circuit_dir/target/${circuit}_verifier.sol"
        local verifier_name
        verifier_name=$(_contract_name "$circuit")
        cp "$circuit_dir/target/${circuit}_verifier.sol" "$REPO_ROOT/src/generated/${circuit}_verifier.sol"
        sed -i '' "s/contract HonkVerifier is/contract ${verifier_name} is/" \
            "$REPO_ROOT/src/generated/${circuit}_verifier.sol"
        "$REPO_ROOT/scripts/patch-pairing-yul.sh" \
            "$REPO_ROOT/src/generated/${circuit}_verifier.sol"
        echo "  done: verifier=${verifier_name}"
        return
    fi

    # Generate witness (nargo 1.0.0-beta.20 writes to workspace target/)
    echo "  executing witness..."
    (cd "$circuit_dir" && "$NARGO" execute)
    local witness_file="$CIRCUITS_DIR/target/$circuit.gz"
    if [[ ! -f "$witness_file" ]]; then
        # Fallback for older nargo versions that write to per-circuit target/
        witness_file="$circuit_dir/target/$circuit.gz"
    fi

    # Generate proof with evm target
    echo "  proving..."
    local proof_dir="$circuit_dir/target/proof"
    rm -r "$proof_dir" 2>/dev/null || true
    "$BB" prove \
        -b "$circuit_json" \
        -w "$witness_file" \
        -t evm \
        --write_vk \
        -o "$circuit_dir/target/proof"

    # Verify natively
    echo "  verifying..."
    "$BB" verify \
        -k "$circuit_dir/target/proof/vk" \
        -p "$circuit_dir/target/proof/proof" \
        -i "$circuit_dir/target/proof/public_inputs" \
        -t evm

    # Regenerate Solidity verifier from the proof's VK (ensures VK consistency)
    echo "  generating solidity verifier..."
    "$BB" write_solidity_verifier \
        -k "$circuit_dir/target/proof/vk" \
        -o "$circuit_dir/target/${circuit}_verifier.sol"

    # Copy to fixtures
    local fixture_dir="$FIXTURES_DIR/$circuit"
    mkdir -p "$fixture_dir"
    cp "$proof_dir/proof" "$fixture_dir/proof"
    cp "$proof_dir/public_inputs" "$fixture_dir/public_inputs"

    # Copy verifier to src/generated/ with unique contract name
    local verifier_name
    verifier_name=$(_contract_name "$circuit")
    cp "$circuit_dir/target/${circuit}_verifier.sol" "$REPO_ROOT/src/generated/${circuit}_verifier.sol"
    sed -i '' "s/contract HonkVerifier is/contract ${verifier_name} is/" \
        "$REPO_ROOT/src/generated/${circuit}_verifier.sol"
    "$REPO_ROOT/scripts/patch-pairing-yul.sh" \
        "$REPO_ROOT/src/generated/${circuit}_verifier.sol"

    local proof_size inputs_size
    proof_size=$(wc -c < "$fixture_dir/proof" | tr -d ' ')
    inputs_size=$(wc -c < "$fixture_dir/public_inputs" | tr -d ' ')
    echo "  done: proof=${proof_size}B, public_inputs=${inputs_size}B, verifier=${verifier_name}"
}

_contract_name() {
    case "$1" in
        compliance)              echo "ComplianceVerifier" ;;
        compliance_signed)       echo "ComplianceSignedVerifier" ;;
        compliance_multi_signed) echo "ComplianceMultiSignedVerifier" ;;
        risk_score)              echo "RiskScoreVerifier" ;;
        risk_score_signed)       echo "RiskScoreSignedVerifier" ;;
        pattern)                 echo "PatternVerifier" ;;
        attestation)             echo "AttestationVerifier" ;;
        membership)              echo "MembershipVerifier" ;;
        non_membership)          echo "NonMembershipVerifier" ;;
        *)                       echo "HonkVerifier" ;;
    esac
}

if [[ $# -gt 0 ]]; then
    generate_fixture "$1"
else
    for circuit_dir in "$CIRCUITS_DIR"/*/; do
        circuit="$(basename "$circuit_dir")"
        # Skip the shared lib (no main.nr) and the workspace `target/` build dir.
        [[ "$circuit" == "shared" ]] && continue
        [[ "$circuit" == "target" ]] && continue
        generate_fixture "$circuit"
    done
fi
