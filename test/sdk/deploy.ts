/**
 * Self-contained contract deployment for SDK tests.
 *
 * Reads forge artifacts from out/ and deploys the full Xochi ZKP stack
 * to a local anvil instance.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  createWalletClient,
  createPublicClient,
  http,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { ANVIL_RPC, DEPLOYER_KEY } from "./anvil";

const REPO_ROOT = resolve(import.meta.dirname, "../..");
const FORGE_OUT = resolve(REPO_ROOT, "out");

export const PROOF_TYPES = {
  COMPLIANCE: 0x01,
  RISK_SCORE: 0x02,
  PATTERN: 0x03,
  ATTESTATION: 0x04,
  MEMBERSHIP: 0x05,
  NON_MEMBERSHIP: 0x06,
} as const;

export const FIXTURE_HASHES = {
  CONFIG_HASH:
    "0x18574f427f33c6c77af53be06544bd749c9a1db855599d950af61ea613df8405" as Hex,
  PROVIDER_SET_HASH:
    "0x14b6becf762f80a24078e62fc9a7eca246b8e406d19962dda817b173f30a94b2" as Hex,
  MEMBERSHIP_ROOT:
    "0x30211953f68b315a285af9496cdaa51517aba83cb3bb40bdd20b2e42eb189fe6" as Hex,
  NON_MEMBERSHIP_ROOT:
    "0x12d001bc3463cb4d3a745f802dffd80c00a2927f77110d1b0a59b9a3bd787b86" as Hex,
  TIER_MERKLE_ROOT:
    "0x15861259068f1398397423d4b3bad764e19c1a68699115ef9ccd090a8a5eba3e" as Hex,
  REPORTING_THRESHOLD: 10000n,
};

export interface DeployedContracts {
  verifier: Address;
  oracle: Address;
  registry: Address;
  verifierAbi: unknown[];
  oracleAbi: unknown[];
  registryAbi: unknown[];
}

function readForgeArtifact(solidityFile: string, contractName: string) {
  const path = resolve(FORGE_OUT, solidityFile, `${contractName}.json`);
  const raw = JSON.parse(readFileSync(path, "utf-8"));
  return {
    abi: raw.abi as unknown[],
    bytecode: raw.bytecode.object as Hex,
    linkReferences: (raw.bytecode.linkReferences || {}) as Record<
      string,
      Record<string, { start: number; length: number }[]>
    >,
  };
}

function linkBytecode(
  bytecode: Hex,
  linkReferences: Record<
    string,
    Record<string, { start: number; length: number }[]>
  >,
  libraries: Record<string, Address>,
): Hex {
  let linked = bytecode.slice(2);
  for (const [, libs] of Object.entries(linkReferences)) {
    for (const [libName, refs] of Object.entries(libs)) {
      const addr = libraries[libName];
      if (!addr) throw new Error(`Missing library address for ${libName}`);
      const addrHex = addr.slice(2).toLowerCase();
      for (const ref of refs) {
        const hexStart = ref.start * 2;
        const hexLen = ref.length * 2;
        linked =
          linked.slice(0, hexStart) + addrHex + linked.slice(hexStart + hexLen);
      }
    }
  }
  return `0x${linked}` as Hex;
}

export async function deployContracts(): Promise<DeployedContracts> {
  const account = privateKeyToAccount(DEPLOYER_KEY);
  const walletClient = createWalletClient({
    account,
    chain: foundry,
    transport: http(ANVIL_RPC),
  });
  const publicClient = createPublicClient({
    chain: foundry,
    transport: http(ANVIL_RPC),
  });

  // Deploy XochiZKPVerifier
  const verifierArtifact = readForgeArtifact(
    "XochiZKPVerifier.sol",
    "XochiZKPVerifier",
  );
  const verifierHash = await walletClient.deployContract({
    abi: verifierArtifact.abi,
    bytecode: verifierArtifact.bytecode,
    args: [account.address],
  });
  const verifierReceipt = await publicClient.waitForTransactionReceipt({
    hash: verifierHash,
  });
  const verifierAddress = verifierReceipt.contractAddress!;

  // Deploy XochiZKPOracle
  const oracleArtifact = readForgeArtifact(
    "XochiZKPOracle.sol",
    "XochiZKPOracle",
  );
  const oracleHash = await walletClient.deployContract({
    abi: oracleArtifact.abi,
    bytecode: oracleArtifact.bytecode,
    args: [verifierAddress, account.address, FIXTURE_HASHES.CONFIG_HASH],
  });
  const oracleReceipt = await publicClient.waitForTransactionReceipt({
    hash: oracleHash,
  });
  const oracleAddress = oracleReceipt.contractAddress!;

  // Deploy generated UltraHonk verifiers
  const circuits: [string, string, number][] = [
    ["compliance_verifier.sol", "ComplianceVerifier", PROOF_TYPES.COMPLIANCE],
    ["risk_score_verifier.sol", "RiskScoreVerifier", PROOF_TYPES.RISK_SCORE],
    [
      "pattern_verifier.sol",
      "PatternVerifier",
      PROOF_TYPES.PATTERN,
    ],
    [
      "attestation_verifier.sol",
      "AttestationVerifier",
      PROOF_TYPES.ATTESTATION,
    ],
    ["membership_verifier.sol", "MembershipVerifier", PROOF_TYPES.MEMBERSHIP],
    [
      "non_membership_verifier.sol",
      "NonMembershipVerifier",
      PROOF_TYPES.NON_MEMBERSHIP,
    ],
  ];

  for (const [solidityFile, contractName, proofType] of circuits) {
    const artifact = readForgeArtifact(solidityFile, contractName);
    let bytecode = artifact.bytecode;

    if (Object.keys(artifact.linkReferences).length > 0) {
      const libraries: Record<string, Address> = {};
      for (const [, libs] of Object.entries(artifact.linkReferences)) {
        for (const libName of Object.keys(libs)) {
          const libArtifact = readForgeArtifact(solidityFile, libName);
          const libHash = await walletClient.deployContract({
            abi: libArtifact.abi,
            bytecode: libArtifact.bytecode,
          });
          const libReceipt = await publicClient.waitForTransactionReceipt({
            hash: libHash,
          });
          libraries[libName] = libReceipt.contractAddress!;
        }
      }
      bytecode = linkBytecode(bytecode, artifact.linkReferences, libraries);
    }

    const hash = await walletClient.deployContract({
      abi: artifact.abi,
      bytecode,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    const addr = receipt.contractAddress!;

    await walletClient.writeContract({
      address: verifierAddress,
      abi: verifierArtifact.abi,
      functionName: "setVerifierInitial",
      args: [proofType, addr],
    });
  }

  // Register merkle roots + reporting threshold
  await walletClient.writeContract({
    address: oracleAddress,
    abi: oracleArtifact.abi,
    functionName: "registerMerkleRoot",
    args: [FIXTURE_HASHES.MEMBERSHIP_ROOT],
  });
  await walletClient.writeContract({
    address: oracleAddress,
    abi: oracleArtifact.abi,
    functionName: "registerMerkleRoot",
    args: [FIXTURE_HASHES.NON_MEMBERSHIP_ROOT],
  });
  await walletClient.writeContract({
    address: oracleAddress,
    abi: oracleArtifact.abi,
    functionName: "registerMerkleRoot",
    args: [FIXTURE_HASHES.TIER_MERKLE_ROOT],
  });
  await walletClient.writeContract({
    address: oracleAddress,
    abi: oracleArtifact.abi,
    functionName: "registerReportingThreshold",
    args: [
      `0x${FIXTURE_HASHES.REPORTING_THRESHOLD.toString(16).padStart(64, "0")}` as Hex,
    ],
  });

  // Deploy SettlementRegistry
  const registryArtifact = readForgeArtifact(
    "SettlementRegistry.sol",
    "SettlementRegistry",
  );
  const registryHash = await walletClient.deployContract({
    abi: registryArtifact.abi,
    bytecode: registryArtifact.bytecode,
    args: [oracleAddress],
  });
  const registryReceipt = await publicClient.waitForTransactionReceipt({
    hash: registryHash,
  });
  const registryAddress = registryReceipt.contractAddress!;

  return {
    verifier: verifierAddress,
    oracle: oracleAddress,
    registry: registryAddress,
    verifierAbi: verifierArtifact.abi,
    oracleAbi: oracleArtifact.abi,
    registryAbi: registryArtifact.abi,
  };
}
