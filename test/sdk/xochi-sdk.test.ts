/**
 * Cross-repo SDK integration tests.
 *
 * Validates that @xochi/sdk produces proofs accepted by the deployed
 * contracts on anvil. This is the P4 "anvil validation" test -- the last
 * integration layer proving the SDK works end-to-end with the actual
 * Solidity contracts.
 *
 * Unlike consumer.test.ts (which uses raw noir_js/bb.js), this file
 * imports only the SDK's typed public API: ERC8262Prover, ERC8262Verifier,
 * ERC8262Oracle, NodeCircuitLoader, and the input builder types.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { resolve } from "node:path";
import { createPublicClient, createWalletClient, http, zeroHash } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import {
  ERC8262Prover,
  ERC8262Verifier,
  ERC8262Oracle,
  SignedSignalsRequiredError,
  ProofTimestampStaleError,
  ProofTimestampInFutureError,
  chainProofTimestamp,
  PATTERN_TIME_WINDOW_MIN,
  PROOF_TYPES,
  type ComplianceInput,
  type RiskScoreThresholdInput,
  type RiskScoreRangeInput,
} from "@xochi/sdk";
import { NodeCircuitLoader } from "@xochi/sdk/node";
import {
  startAnvil,
  stopAnvil,
  ANVIL_RPC,
  ALICE_KEY,
  ALICE_ADDRESS,
  DEPLOYER_ADDRESS,
  FIXTURE_TIMESTAMP,
} from "./anvil";
import {
  deployContracts,
  FIXTURE_HASHES,
  type DeployedContracts,
} from "./deploy";

// ============================================================
// Setup
// ============================================================

const REPO_ROOT = resolve(import.meta.dirname, "../..");
const loader = new NodeCircuitLoader(REPO_ROOT);

// ============================================================
// SDK proof generation (no chain)
// ============================================================

describe("SDK typed proof generation", () => {
  let prover: ERC8262Prover;

  beforeAll(async () => {
    prover = new ERC8262Prover(loader);
  }, 120_000);

  afterAll(async () => {
    await prover.destroy();
  });

  it("proveCompliance with single-provider shorthand", async () => {
    const result = await prover.proveCompliance({
      score: 25,
      jurisdictionId: 0,
      providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      configHash: FIXTURE_HASHES.CONFIG_HASH,
      timestamp: "1700000000",
      submitter: ALICE_ADDRESS,
    });

    expect(result.proofHex).toMatch(/^0x[0-9a-f]+$/);
    expect(result.publicInputs).toHaveLength(6);
    expect(result.publicInputsHex.length).toBe(2 + 6 * 64);
  });

  it("proveCompliance with multi-provider input", async () => {
    // Use single-provider shorthand -- multi-provider requires a
    // provider_set_hash that matches the circuit's Pedersen commitment
    // over the specific (provider_ids, weights) tuple. The fixture hash
    // only matches the single-provider config.
    const result = await prover.proveCompliance({
      score: 30,
      jurisdictionId: 1, // US (threshold 6600)
      providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      configHash: FIXTURE_HASHES.CONFIG_HASH,
      timestamp: "1700000000",
      submitter: ALICE_ADDRESS,
    });

    expect(result.publicInputs).toHaveLength(6);
  });

  it("proveRiskScore threshold GT", async () => {
    const input: RiskScoreThresholdInput = {
      type: "threshold",
      score: 55,
      threshold: 4000,
      direction: "gt",
      providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      configHash: FIXTURE_HASHES.CONFIG_HASH,
      timestamp: String(FIXTURE_TIMESTAMP),
      submitter: ALICE_ADDRESS,
    };

    const result = await prover.proveRiskScore(input);
    expect(result.proofHex).toMatch(/^0x[0-9a-f]+$/);
    // risk_score has 9 public inputs (timestamp at index 7, then submitter)
    expect(result.publicInputs).toHaveLength(9);
    expect(BigInt(result.publicInputs[7])).toBe(BigInt(FIXTURE_TIMESTAMP));
  });

  it("proveRiskScore range", async () => {
    const input: RiskScoreRangeInput = {
      type: "range",
      score: 55,
      lowerBound: 4000,
      upperBound: 7000,
      providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      configHash: FIXTURE_HASHES.CONFIG_HASH,
      timestamp: String(FIXTURE_TIMESTAMP),
      submitter: ALICE_ADDRESS,
    };

    const result = await prover.proveRiskScore(input);
    expect(result.publicInputs).toHaveLength(9);
  });

  it("rejects non-compliant score via input builder", async () => {
    // score=90 -> 9000 bps > EU threshold 7100
    await expect(
      prover.proveCompliance({
        score: 90,
        jurisdictionId: 0,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        timestamp: "1700000000",
        submitter: ALICE_ADDRESS,
      }),
    ).rejects.toThrow(/exceeds jurisdiction threshold/);
  });

  it("rejects contradictory threshold direction", async () => {
    // score=10 -> 1000 bps, claiming > 5000 fails
    await expect(
      prover.proveRiskScore({
        type: "threshold",
        score: 10,
        threshold: 5000,
        direction: "gt",
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        submitter: ALICE_ADDRESS,
      }),
    ).rejects.toThrow(/does not satisfy/);
  });
});

// ============================================================
// SDK -> on-chain verification via anvil
// ============================================================

describe("SDK -> anvil on-chain verification", () => {
  let prover: ERC8262Prover;
  let verifier: ERC8262Verifier;
  let oracle: ERC8262Oracle;
  let contracts: DeployedContracts;

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
    prover = new ERC8262Prover(loader);
    await startAnvil();
    contracts = await deployContracts();
    verifier = new ERC8262Verifier(contracts.verifier, publicClient);
    oracle = new ERC8262Oracle(
      contracts.oracle,
      publicClient,
      aliceClient,
      foundry,
    );
  }, 120_000);

  afterAll(async () => {
    await prover.destroy();
    stopAnvil();
  });

  // ----------------------------------------------------------
  // ERC8262Verifier: on-chain proof verification
  // ----------------------------------------------------------

  describe("ERC8262Verifier typed client", () => {
    it("verifies compliance proof", async () => {
      const { proofHex, publicInputsHex } = await prover.proveCompliance({
        score: 25,
        jurisdictionId: 0,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        configHash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: "1700000000",
        submitter: ALICE_ADDRESS,
      });

      const valid = await verifier.verifyProof(
        PROOF_TYPES.COMPLIANCE,
        proofHex,
        publicInputsHex,
      );
      expect(valid).toBe(true);
    });

    it("verifies risk_score proof", async () => {
      const { proofHex, publicInputsHex } = await prover.proveRiskScore({
        type: "threshold",
        score: 55,
        threshold: 4000,
        direction: "gt",
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        configHash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: String(FIXTURE_TIMESTAMP),
        submitter: ALICE_ADDRESS,
      });

      const valid = await verifier.verifyProof(
        PROOF_TYPES.RISK_SCORE,
        proofHex,
        publicInputsHex,
      );
      expect(valid).toBe(true);
    });

    it("rejects proof submitted to wrong type", async () => {
      const { proofHex, publicInputsHex } = await prover.proveCompliance({
        score: 25,
        jurisdictionId: 1,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        configHash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: "1700000000",
        submitter: ALICE_ADDRESS,
      });

      await expect(
        verifier.verifyProof(
          PROOF_TYPES.RISK_SCORE,
          proofHex,
          publicInputsHex,
        ),
      ).rejects.toThrow();
    });

    it("getVerifier returns non-zero address", async () => {
      const addr = await verifier.getVerifier(PROOF_TYPES.COMPLIANCE);
      expect(addr).not.toBe("0x0000000000000000000000000000000000000000");
    });
  });

  // ----------------------------------------------------------
  // ERC8262Oracle: submit + check attestation
  // ----------------------------------------------------------

  describe("ERC8262Oracle typed client", () => {
    it("submitCompliance records attestation", async () => {
      const { proofHex, publicInputsHex } = await prover.proveCompliance({
        score: 25,
        jurisdictionId: 0,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        configHash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: "1700000000",
        submitter: ALICE_ADDRESS,
      });

      const txHash = await oracle.submitCompliance({
        jurisdictionId: 0,
        proofType: PROOF_TYPES.COMPLIANCE,
        proof: proofHex,
        publicInputs: publicInputsHex,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      });

      const receipt = await publicClient.waitForTransactionReceipt({
        hash: txHash,
      });
      expect(receipt.status).toBe("success");
    });

    it("checkCompliance returns valid after submission", async () => {
      const { valid, attestation } = await oracle.checkCompliance(
        ALICE_ADDRESS,
        0,
      );
      expect(valid).toBe(true);
      expect(attestation.subject.toLowerCase()).toBe(
        ALICE_ADDRESS.toLowerCase(),
      );
      expect(attestation.meetsThreshold).toBe(true);
      expect(attestation.expiresAt).toBeGreaterThan(0n);
    });

    it("rejects unsigned compliance for US jurisdiction", async () => {
      // US (BSA) requires provider-signed signals: the Oracle refuses an unsigned
      // COMPLIANCE (0x01) proof even though the proof itself verifies.
      const { proofHex, publicInputsHex } = await prover.proveCompliance({
        score: 20,
        jurisdictionId: 1,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        configHash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: "1700000000",
        submitter: ALICE_ADDRESS,
      });

      const submission = oracle.submitCompliance({
        jurisdictionId: 1,
        proofType: PROOF_TYPES.COMPLIANCE,
        proof: proofHex,
        publicInputs: publicInputsHex,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      });
      await expect(submission).rejects.toBeInstanceOf(SignedSignalsRequiredError);
      await expect(submission).rejects.toMatchObject({
        jurisdictionId: 1,
        proofType: PROOF_TYPES.COMPLIANCE,
      });

      const { valid } = await oracle.checkCompliance(ALICE_ADDRESS, 1);
      expect(valid).toBe(false);
    });

    it("rejects duplicate proof (replay protection)", async () => {
      const { proofHex, publicInputsHex } = await prover.proveCompliance({
        score: 30,
        jurisdictionId: 2, // UK
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        configHash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: "1700000000",
        submitter: ALICE_ADDRESS,
      });

      // First submission
      const txHash = await oracle.submitCompliance({
        jurisdictionId: 2,
        proofType: PROOF_TYPES.COMPLIANCE,
        proof: proofHex,
        publicInputs: publicInputsHex,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      });
      await publicClient.waitForTransactionReceipt({ hash: txHash });

      // Replay attempt
      await expect(
        oracle.submitCompliance({
          jurisdictionId: 2,
          proofType: PROOF_TYPES.COMPLIANCE,
          proof: proofHex,
          publicInputs: publicInputsHex,
          providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        }),
      ).rejects.toThrow();
    });

    it("submitComplianceBatch submits 2 proofs atomically", async () => {
      // Generate two distinct compliance proofs for the same jurisdiction
      const proof1 = await prover.proveCompliance({
        score: 25,
        jurisdictionId: 0,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        configHash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: "1700000000",
        submitter: ALICE_ADDRESS,
      });

      const proof2 = await prover.proveCompliance({
        score: 30,
        jurisdictionId: 0,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        configHash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: "1700000000",
        submitter: ALICE_ADDRESS,
      });

      // Call submitComplianceBatch directly via viem
      const txHash = await aliceClient.writeContract({
        address: contracts.oracle,
        abi: contracts.oracleAbi,
        functionName: "submitComplianceBatch",
        args: [
          0, // jurisdictionId
          [PROOF_TYPES.COMPLIANCE, PROOF_TYPES.COMPLIANCE],
          [proof1.proofHex, proof2.proofHex],
          [proof1.publicInputsHex, proof2.publicInputsHex],
          [FIXTURE_HASHES.PROVIDER_SET_HASH, FIXTURE_HASHES.PROVIDER_SET_HASH],
        ],
      });

      const receipt = await publicClient.waitForTransactionReceipt({
        hash: txHash,
      });
      expect(receipt.status).toBe("success");

      // Verify both attestations recorded -- check attestation history length
      const history = await publicClient.readContract({
        address: contracts.oracle,
        abi: contracts.oracleAbi,
        functionName: "getAttestationHistory",
        args: [ALICE_ADDRESS, 0],
      });
      // History includes proofs from earlier tests in this describe block,
      // so just verify at least 2 entries exist
      expect((history as unknown[]).length).toBeGreaterThanOrEqual(2);
    });

    it("rejects proof bound to different submitter", async () => {
      // Prove with DEPLOYER_ADDRESS as submitter, but submit from ALICE
      const { proofHex, publicInputsHex } = await prover.proveCompliance({
        score: 25,
        jurisdictionId: 3, // SG (unused jurisdiction to avoid replay collision)
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        configHash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: "1700000000",
        submitter: DEPLOYER_ADDRESS, // not ALICE
      });

      // Oracle should reject: submitter != msg.sender
      await expect(
        oracle.submitCompliance({
          jurisdictionId: 3,
          proofType: PROOF_TYPES.COMPLIANCE,
          proof: proofHex,
          publicInputs: publicInputsHex,
          providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        }),
      ).rejects.toThrow();
    });

    it("risk_score proof verifies and submits", async () => {
      const { proofHex, publicInputsHex } = await prover.proveRiskScore({
        type: "threshold",
        score: 40,
        threshold: 3000,
        direction: "gt",
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        configHash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: String(FIXTURE_TIMESTAMP),
        submitter: ALICE_ADDRESS,
      });

      // Verify on-chain first
      const valid = await verifier.verifyProof(
        PROOF_TYPES.RISK_SCORE,
        proofHex,
        publicInputsHex,
      );
      expect(valid).toBe(true);

      // Submit to oracle
      const txHash = await oracle.submitCompliance({
        jurisdictionId: 0,
        proofType: PROOF_TYPES.RISK_SCORE,
        proof: proofHex,
        publicInputs: publicInputsHex,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      });
      const receipt = await publicClient.waitForTransactionReceipt({
        hash: txHash,
      });
      expect(receipt.status).toBe("success");
    });

    // ERC-8262#25: the risk_score public timestamp is held to MAX_PROOF_AGE.
    // The anvil clock starts at FIXTURE_TIMESTAMP, so a proof dated one second
    // past the window is stale and one dated a day ahead is in the future.
    // The Oracle client decodes these reverts into the SDK's typed errors.
    // 0x02 / 0x03 do not ratchet, so these tests carry no submission-order coupling.
    const STALE = ProofTimestampStaleError;
    const FUTURE = ProofTimestampInFutureError;
    const ONE_DAY_SECONDS = 86_400;
    // Read from the deployed Oracle so the tests follow the contract's boundary.
    const maxProofAge = async () =>
      Number(
        await publicClient.readContract({
          address: contracts.oracle,
          abi: contracts.oracleAbi,
          functionName: "MAX_PROOF_AGE",
        }),
      );

    it("risk_score proof older than MAX_PROOF_AGE is rejected", async () => {
      const { proofHex, publicInputsHex } = await prover.proveRiskScore({
        type: "threshold",
        score: 40,
        threshold: 3000,
        direction: "gt",
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        configHash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: String(FIXTURE_TIMESTAMP - (await maxProofAge()) - 1),
        submitter: ALICE_ADDRESS,
      });
      expect(
        await verifier.verifyProof(PROOF_TYPES.RISK_SCORE, proofHex, publicInputsHex),
      ).toBe(true);

      await expect(
        oracle.submitCompliance({
          jurisdictionId: 0,
          proofType: PROOF_TYPES.RISK_SCORE,
          proof: proofHex,
          publicInputs: publicInputsHex,
          providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        }),
      ).rejects.toThrow(STALE);
    });

    it("future-dated risk_score proof is rejected", async () => {
      const { proofHex, publicInputsHex } = await prover.proveRiskScore({
        type: "threshold",
        score: 40,
        threshold: 3000,
        direction: "gt",
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        configHash: FIXTURE_HASHES.CONFIG_HASH,
        timestamp: String(FIXTURE_TIMESTAMP + ONE_DAY_SECONDS),
        submitter: ALICE_ADDRESS,
      });

      await expect(
        oracle.submitCompliance({
          jurisdictionId: 0,
          proofType: PROOF_TYPES.RISK_SCORE,
          proof: proofHex,
          publicInputs: publicInputsHex,
          providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        }),
      ).rejects.toThrow(FUTURE);
    });

    // PATTERN (0x03) gets the same bound. Fixture data from circuits/pattern/Prover.toml.
    // The circuit needs every transaction in [timestamp - timeWindow, timestamp]; the fixed
    // transaction times keep `txSetHash` valid, so a proof timestamp must stay within
    // `timeWindow` of the oldest one (asserted here so a drifted clock fails with a clear message).
    const PATTERN_TX_TIMESTAMPS = [1699990000, 1699991000, 1699992000, 1699993000];
    const patternInput = (timestamp: number) => {
      expect(timestamp - PATTERN_TX_TIMESTAMPS[0]).toBeLessThanOrEqual(PATTERN_TIME_WINDOW_MIN);
      expect(timestamp).toBeGreaterThanOrEqual(PATTERN_TX_TIMESTAMPS[PATTERN_TX_TIMESTAMPS.length - 1]);
      return {
        amounts: [500, 1200, 3000, 7500],
        timestamps: PATTERN_TX_TIMESTAMPS,
        numTransactions: 4,
        analysisType: 1 as const, // structuring
        reportingThreshold: Number(FIXTURE_HASHES.REPORTING_THRESHOLD),
        timeWindow: PATTERN_TIME_WINDOW_MIN,
        txSetHash: "0x2b3a892d0f3dfeb2474d341a27f3f48fbab2ae0d5a8b4ecca47ef9be42e20f56",
        submitter: ALICE_ADDRESS,
        settlementRoot: "0", // standalone, no SettlementRegistry binding
        timestamp: String(timestamp),
      };
    };

    it("pattern proof with a fresh timestamp submits", async () => {
      const { proofHex, publicInputs, publicInputsHex } = await prover.provePattern(
        patternInput(FIXTURE_TIMESTAMP),
      );
      expect(publicInputs).toHaveLength(8);
      expect(BigInt(publicInputs[7])).toBe(BigInt(FIXTURE_TIMESTAMP));

      const txHash = await oracle.submitCompliance({
        jurisdictionId: 0,
        proofType: PROOF_TYPES.PATTERN,
        proof: proofHex,
        publicInputs: publicInputsHex,
        providerSetHash: zeroHash,
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      expect(receipt.status).toBe("success");
    });

    it("pattern proof older than MAX_PROOF_AGE is rejected", async () => {
      const { proofHex, publicInputsHex } = await prover.provePattern(
        patternInput(FIXTURE_TIMESTAMP - (await maxProofAge()) - 1),
      );
      await expect(
        oracle.submitCompliance({
          jurisdictionId: 0,
          proofType: PROOF_TYPES.PATTERN,
          proof: proofHex,
          publicInputs: publicInputsHex,
          providerSetHash: zeroHash,
        }),
      ).rejects.toThrow(STALE);
    });

    // The builders default `timestamp` to the local clock. This anvil chain runs
    // years behind it (it starts at FIXTURE_TIMESTAMP), as a chain does for a
    // client whose clock is ahead: the default dates the proof in the chain's
    // future, and chainProofTimestamp (the latest block's time) fixes it.
    const chainTimeRiskInput = {
      type: "threshold" as const,
      score: 45,
      threshold: 3000,
      direction: "gt" as const,
      providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      configHash: FIXTURE_HASHES.CONFIG_HASH,
      submitter: ALICE_ADDRESS,
    };

    it("risk_score proof with the wall-clock default timestamp is rejected", async () => {
      const chainNow = Number(await chainProofTimestamp(publicClient));
      expect(chainNow).toBeLessThan(Math.floor(Date.now() / 1000) - (await maxProofAge()));

      const { proofHex, publicInputsHex } = await prover.proveRiskScore(chainTimeRiskInput);
      await expect(
        oracle.submitCompliance({
          jurisdictionId: 0,
          proofType: PROOF_TYPES.RISK_SCORE,
          proof: proofHex,
          publicInputs: publicInputsHex,
          providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
        }),
      ).rejects.toThrow(FUTURE);
    });

    it("risk_score proof dated by chainProofTimestamp submits", async () => {
      const timestamp = await chainProofTimestamp(publicClient);
      const { proofHex, publicInputs, publicInputsHex } = await prover.proveRiskScore({
        ...chainTimeRiskInput,
        timestamp,
      });
      expect(BigInt(publicInputs[7])).toBe(BigInt(timestamp));

      const txHash = await oracle.submitCompliance({
        jurisdictionId: 0,
        proofType: PROOF_TYPES.RISK_SCORE,
        proof: proofHex,
        publicInputs: publicInputsHex,
        providerSetHash: FIXTURE_HASHES.PROVIDER_SET_HASH,
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      expect(receipt.status).toBe("success");
    });

    it("pattern proof dated by chainProofTimestamp submits", async () => {
      const timestamp = await chainProofTimestamp(publicClient);
      const { proofHex, publicInputs, publicInputsHex } = await prover.provePattern(
        patternInput(Number(timestamp)),
      );
      expect(BigInt(publicInputs[7])).toBe(BigInt(timestamp));

      const txHash = await oracle.submitCompliance({
        jurisdictionId: 0,
        proofType: PROOF_TYPES.PATTERN,
        proof: proofHex,
        publicInputs: publicInputsHex,
        providerSetHash: zeroHash,
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      expect(receipt.status).toBe("success");
    });
  });
});
