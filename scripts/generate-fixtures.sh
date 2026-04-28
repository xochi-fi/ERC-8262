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

    if [[ ! -f "$circuit_dir/Prover.toml" ]]; then
        echo "skip: $circuit (no Prover.toml)"
        return
    fi

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

    local proof_size inputs_size
    proof_size=$(wc -c < "$fixture_dir/proof" | tr -d ' ')
    inputs_size=$(wc -c < "$fixture_dir/public_inputs" | tr -d ' ')
    echo "  done: proof=${proof_size}B, public_inputs=${inputs_size}B, verifier=${verifier_name}"
}

_contract_name() {
    case "$1" in
        compliance)        echo "ComplianceVerifier" ;;
        risk_score)        echo "RiskScoreVerifier" ;;
        pattern)           echo "PatternVerifier" ;;
        attestation)       echo "AttestationVerifier" ;;
        membership)        echo "MembershipVerifier" ;;
        non_membership)    echo "NonMembershipVerifier" ;;
        *)                 echo "HonkVerifier" ;;
    esac
}

if [[ $# -gt 0 ]]; then
    generate_fixture "$1"
else
    for circuit_dir in "$CIRCUITS_DIR"/*/; do
        circuit="$(basename "$circuit_dir")"
        [[ "$circuit" == "shared" ]] && continue
        generate_fixture "$circuit"
    done
fi
