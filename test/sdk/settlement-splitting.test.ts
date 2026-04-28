/**
 * Settlement splitting E2E integration test.
 *
 * Full pipeline: planSplit -> proveBatch -> registerTrade ->
 * recordSubSettlement -> pattern proof -> finalizeTrade.
 *
 * Runs against local anvil with deployed Oracle, Verifier,
 * and SettlementRegistry contracts.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  createPublicClient,
  createWalletClient,
  http,
  keccak256,
  encodePacked,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import {
  XochiProver,
  XochiOracle,
  SettlementRegistryClient,
  planSplit,
  proveBatch,
  PROOF_TYPES,
} from "@xochi/sdk";
import { NodeCircuitLoader } from "@xochi/sdk/node";
import { startAnvil, stopAnvil, ANVIL_RPC, ALICE_KEY, FIXTURE_TIMESTAMP } from "./anvil";
import {
  deployContracts,
  FIXTURE_HASHES,
  type DeployedContracts,
} from "./deploy";

const REPO_ROOT = new URL("../..", import.meta.url).pathname;
const EU = 0;
const ETH = 10n ** 18n;

let contracts: DeployedContracts;
let prover: XochiProver;
let oracle: XochiOracle;
let registry: SettlementRegistryClient;

const alice = privateKeyToAccount(ALICE_KEY);

const publicClient = createPublicClient({
  chain: foundry,
  transport: http(ANVIL_RPC),
});

const aliceClient = createWalletClient({
  account: alice,
  chain: foundry,
  transport: http(ANVIL_RPC),
});

beforeAll(async () => {
  await startAnvil();
  contracts = await deployContracts();

  const loader = new NodeCircuitLoader(REPO_ROOT);
  prover = new XochiProver(loader);
  oracle = new XochiOracle(
    contracts.oracle,
    publicClient,
    aliceClient,
    foundry,
  );
  registry = new SettlementRegistryClient(
    contracts.registry,
    publicClient,
    aliceClient,
    foundry,
  );
}, 120_000);

afterAll(async () => {
  await prover.destroy();
  stopAnvil();
});

describe("settlement splitting E2E", () => {
  it("full split -> prove -> register -> settle -> finalize pipeline", async () => {
    // Step 1: Plan the split
    const plan = planSplit(300n * ETH, EU, alice.address, {
      splitThreshold: 100n * ETH,
      maxSubTrades: 10,
      minSubTradeSize: 1n * ETH,
    });

    expect(plan.subTrades).toHaveLength(3);
    expect(plan.subTrades[0].amount).toBe(100n * ETH);
    expect(plan.subTrades[1].amount).toBe(100n * ETH);
    expect(plan.subTrades[2].amount).toBe(100n * ETH);

    // Step 2: Prove all sub-trades
    // anvil is started at FIXTURE_TIMESTAMP (1700000000); pass a matching proof
    // timestamp so the Oracle's MAX_PROOF_AGE (1h) check passes.
    const batchResult = await proveBatch(prover, plan, {
      score: 25,
      jurisdictionId: EU,
      providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      configHash: FIXTURE_HASHES.CONFIG_HASH,
      submitter: alice.address,
      timestamp: String(FIXTURE_TIMESTAMP + 5),
    });

    expect(batchResult.proofs).toHaveLength(3);
    expect(batchResult.tradeId).toBe(plan.tradeId);

    // Step 3: Register the trade on-chain
    const registerTx = await registry.registerTrade(
      plan.tradeId,
      EU,
      plan.subTrades.length,
    );
    await publicClient.waitForTransactionReceipt({ hash: registerTx });
    expect(registerTx).toMatch(/^0x/);

    // Verify settlement was created
    const settlement = await registry.getSettlement(plan.tradeId);
    expect(settlement.subject.toLowerCase()).toBe(alice.address.toLowerCase());
    expect(Number(settlement.subTradeCount)).toBe(3);
    expect(Number(settlement.settledCount)).toBe(0);
    expect(settlement.finalized).toBe(false);

    // Step 4: Submit each proof to Oracle, then record in Registry
    const proofHashes: Hex[] = [];

    for (const { index, proofResult } of batchResult.proofs) {
      // Submit to Oracle and wait for mining
      const submitTx = await oracle.submitCompliance({
        jurisdictionId: EU,
        proofType: PROOF_TYPES.COMPLIANCE,
        proof: proofResult.proofHex,
        publicInputs: proofResult.publicInputsHex,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      });
      await publicClient.waitForTransactionReceipt({ hash: submitTx });

      // Compute proofHash the same way the Oracle does
      const proofHash = keccak256(
        encodePacked(
          ["bytes", "uint8"],
          [proofResult.proofHex, PROOF_TYPES.COMPLIANCE],
        ),
      );
      proofHashes.push(proofHash);

      // Record in Registry and wait
      const recordTx = await registry.recordSubSettlement(plan.tradeId, index, proofHash);
      await publicClient.waitForTransactionReceipt({ hash: recordTx });
    }

    // Verify all sub-settlements recorded
    const midSettlement = await registry.getSettlement(plan.tradeId);
    expect(Number(midSettlement.settledCount)).toBe(3);

    const subs = await registry.getSubSettlements(plan.tradeId);
    expect(subs.length).toBe(3);

    // Step 5: Generate pattern proof using fixture data from circuits/pattern/Prover.toml.
    // The txSetHash is a Pedersen commitment that must match the circuit's expected value.
    // We use the circuit's own test fixture for a known-good input set.
    const patternResult = await prover.provePattern({
      amounts: [500, 1200, 3000, 7500],
      timestamps: [1700000000, 1700001000, 1700002000, 1700003000],
      numTransactions: 4,
      analysisType: 1, // structuring
      reportingThreshold: Number(FIXTURE_HASHES.REPORTING_THRESHOLD),
      timeWindow: 86400, // 24 hours (SDK minimum)
      txSetHash: "0x2231d26d52515af30cbb6e91834cdb9e3d1d36575f160cbb4f6ebbb3c3dd8dad",
      submitter: alice.address,
    });

    const patternSubmitTx = await oracle.submitCompliance({
      jurisdictionId: EU,
      proofType: PROOF_TYPES.PATTERN,
      proof: patternResult.proofHex,
      publicInputs: patternResult.publicInputsHex,
      providerSetHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
    });
    await publicClient.waitForTransactionReceipt({ hash: patternSubmitTx });

    const patternProofHash = keccak256(
      encodePacked(
        ["bytes", "uint8"],
        [patternResult.proofHex, PROOF_TYPES.PATTERN],
      ),
    );

    // Verify Oracle stored the proof type
    const storedType = await oracle.getProofType(patternProofHash);
    expect(storedType).toBe(PROOF_TYPES.PATTERN);

    // Step 6: Finalize the trade.
    // Audit H-2: pass the original publicInputs bytes so the registry can verify
    // hash equality against attestation.publicInputsHash AND analysis_type==1.
    const finalizeTx = await registry.finalizeTrade(
      plan.tradeId,
      patternProofHash,
      patternResult.publicInputsHex,
    );
    await publicClient.waitForTransactionReceipt({ hash: finalizeTx });
    expect(finalizeTx).toMatch(/^0x/);

    // Verify finalized state
    const finalSettlement = await registry.getSettlement(plan.tradeId);
    expect(finalSettlement.finalized).toBe(true);
    expect(Number(finalSettlement.settledCount)).toBe(3);
  }, 180_000);

  it("finalizeTrade rejects non-PATTERN proof type", async () => {
    // Quick setup: register + settle a 2-sub-trade split
    const plan = planSplit(200n * ETH, EU, alice.address, {
      splitThreshold: 100n * ETH,
    });

    // anvil is started at FIXTURE_TIMESTAMP (1700000000); pass a matching proof
    // timestamp so the Oracle's MAX_PROOF_AGE (1h) check passes.
    const batchResult = await proveBatch(prover, plan, {
      score: 25,
      jurisdictionId: EU,
      providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      configHash: FIXTURE_HASHES.CONFIG_HASH,
      submitter: alice.address,
      timestamp: String(FIXTURE_TIMESTAMP + 5),
    });

    const regTx = await registry.registerTrade(plan.tradeId, EU, 2);
    await publicClient.waitForTransactionReceipt({ hash: regTx });

    for (const { index, proofResult } of batchResult.proofs) {
      const tx = await oracle.submitCompliance({
        jurisdictionId: EU,
        proofType: PROOF_TYPES.COMPLIANCE,
        proof: proofResult.proofHex,
        publicInputs: proofResult.publicInputsHex,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      });
      await publicClient.waitForTransactionReceipt({ hash: tx });

      const proofHash = keccak256(
        encodePacked(
          ["bytes", "uint8"],
          [proofResult.proofHex, PROOF_TYPES.COMPLIANCE],
        ),
      );
      const recTx = await registry.recordSubSettlement(plan.tradeId, index, proofHash);
      await publicClient.waitForTransactionReceipt({ hash: recTx });
    }

    // Try to finalize with a COMPLIANCE proof instead of PATTERN
    const complianceProofHash = keccak256(
      encodePacked(
        ["bytes", "uint8"],
        [batchResult.proofs[0].proofResult.proofHex, PROOF_TYPES.COMPLIANCE],
      ),
    );

    // Even with public inputs, a COMPLIANCE proofHash is rejected because
    // oracle.getProofType returns COMPLIANCE not PATTERN.
    await expect(
      registry.finalizeTrade(
        plan.tradeId,
        complianceProofHash,
        batchResult.proofs[0].proofResult.publicInputsHex,
      ),
    ).rejects.toThrow();
  }, 180_000);
});
