"use client";

import { useState, useCallback } from "react";
import {
  connectLedger,
  sendChunkedAPDUs,
  buildChunkedAPDUs,
  type LedgerDevice,
} from "../clear-signing-hw/ledger";

const INS_VERIFY_VK_STORAGE = 0x64;
const RPC = "https://ethereum-rpc.publicnode.com";
const TEXT_KEY = "vkHash:ERC20_approve";
const VKEY_PATH = "/circuits/ERC20_approve/vkey.json";

// Discovered layout: versionable_texts at base_slot=10, version=0
const BASE_SLOT = 10;
const VERSION = 0;

type Step = {
  label: string;
  status: "pending" | "running" | "success" | "error";
  detail?: string;
};

export default function VerifyVKPage() {
  const [ensName, setEnsName] = useState("veryklear.eth");
  const [vkHashOnChain, setVkHashOnChain] = useState("");
  const [vkHashEditable, setVkHashEditable] = useState("");
  const [localHash, setLocalHash] = useState("");
  const [steps, setSteps] = useState<Step[]>([]);
  const [running, setRunning] = useState(false);
  const [proofPayload, setProofPayload] = useState<string | null>(null);
  const [ledger, setLedger] = useState<LedgerDevice | null>(null);
  const [hwResult, setHwResult] = useState<{
    match: boolean;
    extracted: string;
  } | null>(null);

  const updateStep = useCallback(
    (idx: number, update: Partial<Step>) =>
      setSteps((s) =>
        s.map((st, i) => (i === idx ? { ...st, ...update } : st))
      ),
    []
  );

  /* ── Compute storage slots ──────────────────────────────────── */
  function computeSlots(ethers: typeof import("ethers"), ensNode: string) {
    const keyBytes = ethers.toUtf8Bytes(TEXT_KEY);
    // Level 1: versionable_texts mapping(uint64 => ...) at BASE_SLOT
    const s1 = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256"],
        [VERSION, BASE_SLOT]
      )
    );
    // Level 2: mapping(bytes32 => ...) at s1
    const s2 = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32"],
        [ensNode, s1]
      )
    );
    // Level 3: mapping(string => string) — keccak256(bytes(key) || s2)
    const s3 = ethers.keccak256(ethers.concat([keyBytes, s2]));
    // Long string data slots
    const dataSlot0 = ethers.keccak256(s3);
    const dataSlot1 =
      "0x" + (BigInt(dataSlot0) + 1n).toString(16).padStart(64, "0");
    return { s3, dataSlot0, dataSlot1 };
  }

  /* ── Fetch ENS + build storage proof ────────────────────────── */
  const fetchAndProve = useCallback(async () => {
    setRunning(true);
    setHwResult(null);
    setProofPayload(null);

    const newSteps: Step[] = [
      { label: "Resolve ENS name", status: "running" },
      { label: "Fetch VK hash from text record", status: "pending" },
      { label: "Compute local VK hash", status: "pending" },
      { label: "Compute storage slots", status: "pending" },
      { label: "Fetch storage proofs (eth_getProof)", status: "pending" },
      { label: "Serialize for Ledger", status: "pending" },
    ];
    setSteps(newSteps);

    try {
      const ethers = await import("ethers");
      const provider = new ethers.JsonRpcProvider(RPC);

      // Step 0: Resolve
      const resolver = await provider.getResolver(ensName);
      if (!resolver) throw new Error("No resolver found for " + ensName);
      updateStep(0, {
        status: "success",
        detail: `Resolver: ${resolver.address}`,
      });

      // Step 1: Fetch text record
      updateStep(1, { status: "running" });
      const onChain = await resolver.getText(TEXT_KEY);
      if (!onChain) throw new Error(`No text record for "${TEXT_KEY}"`);
      setVkHashOnChain(onChain);
      setVkHashEditable(onChain);
      updateStep(1, {
        status: "success",
        detail: `${onChain.slice(0, 24)}...`,
      });

      // Step 2: Local VK hash
      updateStep(2, { status: "running" });
      const vkeyResp = await fetch(VKEY_PATH);
      const vkeyText = await vkeyResp.text();
      const hashBuf = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(vkeyText)
      );
      const lh = Array.from(new Uint8Array(hashBuf))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      setLocalHash(lh);
      updateStep(2, {
        status: lh === onChain ? "success" : "error",
        detail:
          lh === onChain
            ? "Matches on-chain \u2713"
            : `Mismatch! Local: ${lh.slice(0, 16)}...`,
      });

      // Step 3: Compute storage slots
      updateStep(3, { status: "running" });
      const node = ethers.namehash(ensName);
      const { s3, dataSlot0, dataSlot1 } = computeSlots(ethers, node);
      updateStep(3, {
        status: "success",
        detail: `String slot: ${s3.slice(0, 18)}... \u2192 data at ${dataSlot0.slice(0, 12)}... +1`,
      });

      // Step 4: eth_getProof for both data slots
      updateStep(4, { status: "running" });
      const proof = await provider.send("eth_getProof", [
        resolver.address,
        [dataSlot0, dataSlot1],
        "latest",
      ]);
      const storageHash: string = proof.storageHash;
      const sp0 = proof.storageProof[0];
      const sp1 = proof.storageProof[1];
      updateStep(4, {
        status: "success",
        detail: `storageHash=${storageHash.slice(0, 18)}... slot0: ${sp0.proof.length} nodes, slot1: ${sp1.proof.length} nodes`,
      });

      // Step 5: Serialize for Nano
      updateStep(5, { status: "running" });
      const expectedHash = vkHashEditable || onChain;
      const hex = serializePayload(
        storageHash,
        dataSlot0,
        sp0.proof as string[],
        dataSlot1,
        sp1.proof as string[],
        expectedHash
      );
      setProofPayload(hex);
      updateStep(5, {
        status: "success",
        detail: `${hex.length / 2} bytes, ${Math.ceil(hex.length / 2 / 250)} chunks`,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setSteps((s) =>
        s.map((st) =>
          st.status === "running"
            ? { ...st, status: "error", detail: msg }
            : st
        )
      );
    } finally {
      setRunning(false);
    }
  }, [ensName, vkHashEditable, updateStep]);

  /* ── Send to Ledger ─────────────────────────────────────────── */
  const verifyOnLedger = useCallback(async () => {
    if (!proofPayload) return;
    setHwResult(null);
    try {
      let dev = ledger;
      if (!dev) {
        dev = await connectLedger();
        setLedger(dev);
      }

      let payload = proofPayload;
      if (vkHashEditable && vkHashEditable !== vkHashOnChain) {
        payload = payload.slice(0, -64) + vkHashEditable.padStart(64, "0");
      }

      const chunks = buildChunkedAPDUs(INS_VERIFY_VK_STORAGE, payload);
      const result = await sendChunkedAPDUs(dev, chunks);
      const match = result.sw === 0x9000 && result.data[0] === 0x01;
      const extracted = Array.from(result.data.slice(1, 33))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      setHwResult({ match, extracted });
    } catch (e) {
      setHwResult({
        match: false,
        extracted: e instanceof Error ? e.message : "error",
      });
    }
  }, [proofPayload, ledger, vkHashEditable, vkHashOnChain]);

  return (
    <main className="font-serif max-w-[680px] mx-auto px-6 py-20 md:py-32">
      <header className="mb-12">
        <h1 className="text-3xl md:text-4xl font-semibold tracking-tight leading-tight">
          Verify VK On-Chain
        </h1>
        <p className="mt-3 text-secondary text-base">
          Fetch the Groth16 verification key hash from ENS, generate an
          Ethereum storage proof, and verify it on the Ledger Nano S+.
        </p>
      </header>

      {/* ENS input */}
      <section className="mb-6 rounded-lg border border-[var(--border)] p-6">
        <label className="text-sm font-semibold uppercase tracking-wider text-secondary block mb-2">
          ENS Name
        </label>
        <div className="flex gap-3">
          <input
            type="text"
            value={ensName}
            onChange={(e) => setEnsName(e.target.value)}
            className="flex-1 px-3 py-2 rounded border border-[var(--border)] font-mono text-sm bg-transparent"
          />
          <button
            onClick={fetchAndProve}
            disabled={running || !ensName}
            className={`px-4 py-2 rounded-lg font-semibold text-sm transition-all ${
              running
                ? "bg-gray-300 text-gray-500 cursor-not-allowed"
                : "bg-black text-white hover:bg-gray-800 cursor-pointer"
            }`}
          >
            {running ? "Fetching..." : "Fetch & Prove"}
          </button>
        </div>
      </section>

      {/* Steps */}
      {steps.length > 0 && (
        <section className="mb-6 space-y-2">
          {steps.map((step, i) => (
            <div
              key={i}
              className={`flex items-start gap-3 p-3 rounded-lg border text-sm ${
                step.status === "success"
                  ? "border-emerald-500/30 bg-emerald-500/5"
                  : step.status === "error"
                    ? "border-red-500/30 bg-red-500/5"
                    : step.status === "running"
                      ? "border-blue-500/30 bg-blue-500/5"
                      : "border-[var(--border)]"
              }`}
            >
              <span className="mt-0.5">
                {step.status === "success"
                  ? "\u2705"
                  : step.status === "error"
                    ? "\u274c"
                    : step.status === "running"
                      ? "\u23f3"
                      : "\u2022"}
              </span>
              <div className="min-w-0 flex-1">
                <p className="font-semibold">{step.label}</p>
                {step.detail && (
                  <p className="text-secondary mt-0.5 font-mono text-xs break-all">
                    {step.detail}
                  </p>
                )}
              </div>
            </div>
          ))}
        </section>
      )}

      {/* VK hash comparison */}
      {vkHashOnChain && (
        <section className="mb-6 rounded-lg border border-[var(--border)] p-6 space-y-4">
          <div>
            <label className="text-xs font-semibold uppercase tracking-wider text-secondary block mb-1">
              VK Hash from ENS (on-chain)
            </label>
            <p className="font-mono text-xs break-all text-emerald-700">
              {vkHashOnChain}
            </p>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wider text-secondary block mb-1">
              Local SHA256(vkey.json)
            </label>
            <p
              className={`font-mono text-xs break-all ${
                localHash === vkHashOnChain
                  ? "text-emerald-700"
                  : "text-red-600"
              }`}
            >
              {localHash || "..."}
            </p>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wider text-secondary block mb-1">
              Expected VK Hash (editable — modify to test rejection)
            </label>
            <input
              type="text"
              value={vkHashEditable}
              onChange={(e) => setVkHashEditable(e.target.value)}
              className="w-full px-3 py-2 rounded border border-[var(--border)] font-mono text-xs bg-transparent"
            />
          </div>
        </section>
      )}

      {/* Verify on Ledger */}
      {proofPayload && (
        <button
          onClick={verifyOnLedger}
          className="w-full py-4 px-6 rounded-lg font-semibold text-lg bg-black text-white hover:bg-gray-800 active:scale-[0.98] transition-all cursor-pointer mb-6"
        >
          &#x1f50f; Verify VK on Ledger Nano S+
        </button>
      )}

      {/* Hardware result */}
      {hwResult && (
        <section
          className={`mb-6 rounded-lg border-2 p-6 ${
            hwResult.match
              ? "border-emerald-500/40 bg-emerald-500/5"
              : "border-red-500/40 bg-red-500/5"
          }`}
        >
          <div className="flex items-center gap-2 mb-3">
            <span className="text-2xl">
              {hwResult.match ? "\u2705" : "\u274c"}
            </span>
            <h2
              className={`text-lg font-semibold ${
                hwResult.match ? "text-emerald-800" : "text-red-800"
              }`}
            >
              {hwResult.match
                ? "VK Hash Verified on Hardware"
                : "VK Hash Mismatch"}
            </h2>
          </div>
          <div className="space-y-2 text-xs font-mono">
            <div>
              <span className="text-secondary">Extracted from MPT: </span>
              <span className="break-all">{hwResult.extracted}</span>
            </div>
            <div>
              <span className="text-secondary">Expected: </span>
              <span className="break-all">{vkHashEditable}</span>
            </div>
          </div>
          <p className="text-xs text-secondary mt-3">
            The Ledger verified 2 Ethereum MPT storage proofs (long string split
            across 2 slots) using Keccak-256, confirming the VK hash is
            authentically stored on-chain in the ENS PublicResolver.
          </p>
        </section>
      )}

      <p className="text-xs text-secondary leading-relaxed mt-8">
        Powered by ZKNOX. Modify the expected hash to demonstrate tamper detection.
      </p>
    </main>
  );
}

/* ── Serialization ─────────────────────────────────────────────
 * Format for Nano (INS 0x64):
 *   storageHash(32) | nProofs(1) |
 *     slot_0(32) | nNodes_0(1) | [nodeLen(2) | nodeData]... |
 *     slot_1(32) | nNodes_1(1) | [nodeLen(2) | nodeData]... |
 *   expectedHash(32)
 *
 * The Nano verifies both MPT proofs, extracts 32+32 bytes,
 * interprets as hex string, converts to 32-byte hash, compares.
 */
function serializePayload(
  storageHash: string,
  slot0: string,
  proof0: string[],
  slot1: string,
  proof1: string[],
  expectedVkHash: string
): string {
  const parts: string[] = [];

  // storageHash (32 bytes)
  parts.push(storageHash.replace("0x", "").padStart(64, "0"));

  // nProofs (1 byte) = 2
  parts.push("02");

  // Proof 0
  parts.push(slot0.replace("0x", "").padStart(64, "0"));
  parts.push(proof0.length.toString(16).padStart(2, "0"));
  for (const nodeHex of proof0) {
    const data = nodeHex.replace("0x", "");
    parts.push((data.length / 2).toString(16).padStart(4, "0"));
    parts.push(data);
  }

  // Proof 1
  parts.push(slot1.replace("0x", "").padStart(64, "0"));
  parts.push(proof1.length.toString(16).padStart(2, "0"));
  for (const nodeHex of proof1) {
    const data = nodeHex.replace("0x", "");
    parts.push((data.length / 2).toString(16).padStart(4, "0"));
    parts.push(data);
  }

  // expectedVkHash (32 bytes) — hex string decoded to bytes
  const hashHex = expectedVkHash.replace("0x", "").padStart(64, "0");
  parts.push(hashHex);

  return parts.join("");
}
