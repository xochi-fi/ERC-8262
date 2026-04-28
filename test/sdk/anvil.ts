/**
 * Minimal anvil lifecycle for SDK tests.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { createPublicClient, http } from "viem";
import { foundry } from "viem/chains";

export const ANVIL_PORT = 8547;
export const ANVIL_RPC = `http://127.0.0.1:${ANVIL_PORT}`;

// Fixture proofs use this timestamp; anvil must start here so proofs
// pass the Oracle's MAX_PROOF_AGE (1 hour) check.
export const FIXTURE_TIMESTAMP = 1700000000;

// anvil account #0
export const DEPLOYER_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
export const DEPLOYER_ADDRESS =
  "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as const;

// anvil account #1
export const ALICE_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as const;
export const ALICE_ADDRESS =
  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" as const;

let anvilProcess: ChildProcess | null = null;

export async function startAnvil(): Promise<void> {
  if (anvilProcess) return;

  const anvilBin =
    process.env.ANVIL_BIN ||
    [
      `${process.env.HOME}/.config/.foundry/bin/anvil`,
      `${process.env.HOME}/.foundry/bin/anvil`,
      "anvil",
    ].find((p) => {
      try {
        accessSync(p, constants.X_OK);
        return true;
      } catch {
        return false;
      }
    }) ||
    "anvil";

  anvilProcess = spawn(
    anvilBin,
    [
      "--port",
      String(ANVIL_PORT),
      "--silent",
      "--code-size-limit",
      "65536",
      "--timestamp",
      String(FIXTURE_TIMESTAMP),
    ],
    { stdio: "ignore", detached: false },
  );

  anvilProcess.on("error", (err) => {
    throw new Error(`anvil failed to start: ${err.message}`);
  });

  const client = createPublicClient({
    chain: foundry,
    transport: http(ANVIL_RPC),
  });

  for (let i = 0; i < 30; i++) {
    try {
      await client.getBlockNumber();
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  throw new Error("anvil did not become ready within 6s");
}

export function stopAnvil(): void {
  if (anvilProcess) {
    anvilProcess.kill("SIGTERM");
    anvilProcess = null;
  }
}
