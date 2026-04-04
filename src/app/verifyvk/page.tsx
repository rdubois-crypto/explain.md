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

  /* ── Fetch ENS + build storage proof ─────────────────────────── */
  const fetchAndProve = useCallback(async () => {
    setRunning(true);
    setHwResult(null);
    setProofPayload(null);

    const newSteps: Step[] = [
      { label: "Resolve ENS name", status: "running" },
      { label: "Fetch VK hash from text record", status: "pending" },
      { label: "Compute local VK hash", status: "pending" },
      { label: "Find storage slot", status: "pending" },
      { label: "Fetch storage proof (eth_getProof)", status: "pending" },
      { label: "Serialize for Ledger", status: "pending" },
    ];
    setSteps(newSteps);

    try {
      const { ethers } = await import("ethers");
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
      if (!onChain) throw new Error(`No text record for key "${TEXT_KEY}"`);
      setVkHashOnChain(onChain);
      setVkHashEditable(onChain);
      updateStep(1, { status: "success", detail: onChain.slice(0, 24) + "..." });

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
            ? "Matches on-chain"
            : `Mismatch! Local: ${lh.slice(0, 16)}...`,
      });

      // Step 3: Find storage slot
      updateStep(3, { status: "running" });
      const node = ethers.namehash(ensName);
      const keyHash = ethers.keccak256(ethers.toUtf8Bytes(TEXT_KEY));
      let foundSlot: string | null = null;

      for (let base = 0; base < 20; base++) {
        const outer = ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(
            ["bytes32", "uint256"],
            [node, base]
          )
        );
        const inner = ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(
            ["bytes32", "bytes32"],
            [keyHash, outer]
          )
        );
        const raw = await provider.getStorage(resolver.address, inner);
        if (raw !== "0x" + "00".repeat(32)) {
          foundSlot = inner;
          updateStep(3, {
            status: "success",
            detail: `base_slot=${base}, slot=${inner.slice(0, 18)}...`,
          });
          break;
        }
      }
      if (!foundSlot) throw new Error("Storage slot not found (tried 0-19)");

      // Step 4: eth_getProof
      updateStep(4, { status: "running" });
      const proof = await provider.send("eth_getProof", [
        resolver.address,
        [foundSlot],
        "latest",
      ]);
      const storageHash: string = proof.storageHash;
      const spf = proof.storageProof[0];
      updateStep(4, {
        status: "success",
        detail: `${spf.proof.length} MPT nodes, storageHash=${storageHash.slice(0, 18)}...`,
      });

      // Step 5: Serialize
      updateStep(5, { status: "running" });
      const hex = serializePayload(
        storageHash,
        foundSlot,
        spf.proof as string[],
        vkHashEditable || onChain
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
          st.status === "running" ? { ...st, status: "error", detail: msg } : st
        )
      );
    } finally {
      setRunning(false);
    }
  }, [ensName, vkHashEditable, updateStep]);

  /* ── Send to Ledger ──────────────────────────────────────────── */
  const verifyOnLedger = useCallback(async () => {
    if (!proofPayload) return;
    setHwResult(null);
    try {
      let dev = ledger;
      if (!dev) {
        dev = await connectLedger();
        setLedger(dev);
      }

      // Rebuild payload with the editable hash (user may have changed it)
      let payload = proofPayload;
      if (vkHashEditable && vkHashEditable !== vkHashOnChain) {
        // Replace last 32 bytes (expectedVkHash) with edited value
        const edited = vkHashEditable.replace("0x", "").padStart(64, "0");
        payload = payload.slice(0, -64) + edited;
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
            placeholder="veryklear.eth"
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

      {/* Verify on Ledger button */}
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
            The Ledger verified the Ethereum Merkle Patricia Trie storage proof
            using Keccak-256, confirming the VK hash is authentically stored
            on-chain in the ENS resolver contract.
          </p>
        </section>
      )}

      {/* Footer */}
      <p className="text-xs text-secondary leading-relaxed mt-8">
        Powered by ZKNOX. The storage proof is verified entirely on the Ledger
        Nano S+ secure element using Keccak-256 over the MPT nodes. Modify the
        expected hash above to demonstrate that the Nano detects tampering.
      </p>
    </main>
  );
}

/* ── Serialization ─────────────────────────────────────────────── */

function serializePayload(
  storageHash: string,
  slot: string,
  proofNodes: string[],
  expectedVkHash: string
): string {
  const parts: string[] = [];
  parts.push(storageHash.replace("0x", "").padStart(64, "0"));
  parts.push(slot.replace("0x", "").padStart(64, "0"));
  parts.push(proofNodes.length.toString(16).padStart(2, "0"));
  for (const nodeHex of proofNodes) {
    const data = nodeHex.replace("0x", "");
    const len = data.length / 2;
    parts.push(len.toString(16).padStart(4, "0"));
    parts.push(data);
  }
  parts.push(expectedVkHash.replace("0x", "").padStart(64, "0"));
  return parts.join("");
}
