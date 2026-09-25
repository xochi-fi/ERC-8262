/**
 * Generated-verifier drift guard.
 *
 * Every src/generated/*_verifier.sol embeds the VK_HASH of the circuit it was
 * generated from. If a circuit (or the shared library it imports) changes and
 * its verifier is not regenerated, proofs from the current circuit fail
 * on-chain. This happened once: a shared-library change regenerated only
 * compliance_verifier.sol, leaving 0x07 and 0x09 pinned to stale VKs.
 *
 * This test derives the EVM verification key of each compiled circuit with
 * bb.js (the pinned backend), renders the Solidity verifier for it, and
 * requires the rendered VK_HASH and NUMBER_OF_PUBLIC_INPUTS to equal the
 * committed ones. Fix a failure with `make fixtures` (see scripts/generate-fixtures.sh).
 *
 * Requires compiled circuits: `cd circuits && nargo compile --workspace`.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";

const REPO_ROOT = resolve(import.meta.dirname, "../..");

const CIRCUITS = [
  "compliance",
  "risk_score",
  "pattern",
  "attestation",
  "membership",
  "non_membership",
  "compliance_signed",
  "risk_score_signed",
  "compliance_multi_signed",
] as const;

function circuitPath(name: string): string {
  const workspace = resolve(REPO_ROOT, `circuits/target/${name}.json`);
  const perProject = resolve(REPO_ROOT, `circuits/${name}/target/${name}.json`);
  if (existsSync(workspace)) return workspace;
  if (existsSync(perProject)) return perProject;
  throw new Error(
    `compiled circuit ${name} not found (run: cd circuits && nargo compile --workspace)`,
  );
}

function constant(source: string, name: string, file: string): string {
  const match = source.match(new RegExp(`^uint256 constant ${name} = (0x[0-9a-fA-F]+|\\d+);`, "m"));
  if (!match) throw new Error(`${name} not found in ${file}`);
  return match[1].toLowerCase();
}

describe("generated verifiers match compiled circuits", () => {
  let api: Barretenberg;

  beforeAll(async () => {
    api = await Barretenberg.new();
  });

  afterAll(async () => {
    await api.destroy();
  });

  it.each(CIRCUITS)("%s verifier VK_HASH matches the compiled circuit", async (name) => {
    const circuit = JSON.parse(readFileSync(circuitPath(name), "utf-8"));
    const backend = new UltraHonkBackend(circuit.bytecode, api);
    const vk = await backend.getVerificationKey({ verifierTarget: "evm" });
    const expected = await backend.getSolidityVerifier(vk, { verifierTarget: "evm" });

    const file = `src/generated/${name}_verifier.sol`;
    const committed = readFileSync(resolve(REPO_ROOT, file), "utf-8");

    expect(
      constant(committed, "VK_HASH", file),
      `${file} is stale: regenerate with \`make fixtures\``,
    ).toBe(constant(expected, "VK_HASH", "bb.js output"));
    expect(constant(committed, "NUMBER_OF_PUBLIC_INPUTS", file)).toBe(
      constant(expected, "NUMBER_OF_PUBLIC_INPUTS", "bb.js output"),
    );
  });
});
