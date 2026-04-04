"use client";

import React, { useState, useCallback, useRef, useEffect } from "react";
import { ExternalLink, Disclosure } from "../components";
import { findSpec, findSpecFromEns } from "../clear-signing/engine/specs";
import { extractSelector, decodeCalldata } from "../clear-signing/engine/decoder";
import { evaluateIntent, collectAllTemplates } from "../clear-signing/engine/evaluator";
import {
  resolveAddressAsync,
  formatAddress,
  formatTokenAmount,
} from "../clear-signing/engine/resolver";
import {
  hasCircuit,
  generateAndVerifyProof,
  getVkeyHash,
  type ProofResult,
} from "../clear-signing/engine/prover";
import { DEMO_EXAMPLE } from "../clear-signing/engine/examples";
import {
  connectLedger,
  sendChunkedAPDUs,
  buildChunkedAPDUs,
  type LedgerDevice,
} from "./ledger";

const INS_CLEAR_SIGN = 0x63;

/** Serialize a BLS12-381 G1 point [x,y,z] → 96 bytes BE */
function g1ToBytes(pt: string[]): Uint8Array {
  const z = pt[2] !== undefined ? BigInt(pt[2]) : 1n;
  if (z === 0n) return new Uint8Array(96);
  const buf = new Uint8Array(96);
  bigintToBE(BigInt(pt[0]), 48, buf, 0);
  bigintToBE(BigInt(pt[1]), 48, buf, 48);
  return buf;
}

/** Serialize a BLS12-381 G2 point [[x0,x1],[y0,y1],z] → 192 bytes BE */
function g2ToBytes(pt: string[][]): Uint8Array {
  const buf = new Uint8Array(192);
  bigintToBE(BigInt(pt[0][0]), 48, buf, 0);
  bigintToBE(BigInt(pt[0][1]), 48, buf, 48);
  bigintToBE(BigInt(pt[1][0]), 48, buf, 96);
  bigintToBE(BigInt(pt[1][1]), 48, buf, 144);
  return buf;
}

/** BigInt → big-endian bytes at offset in buf */
function bigintToBE(n: bigint, len: number, buf: Uint8Array, off: number) {
  let v = n;
  for (let i = off + len - 1; i >= off; i--) {
    buf[i] = Number(v & 0xFFn);
    v >>= 8n;
  }
}

/** Build CLEAR_SIGN payload: text + VK + proof + publicSignals */
function buildClearSignPayload(
  text: string,
  vkey: Record<string, unknown>,
  proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[] },
  publicSignals: string[]
): string {
  const textBytes = new TextEncoder().encode(text);
  const nPub = publicSignals.length;

  // Header: text_len(2) + text + nPublic(1)
  const parts: Uint8Array[] = [];
  const header = new Uint8Array(2);
  header[0] = (textBytes.length >> 8) & 0xFF;
  header[1] = textBytes.length & 0xFF;
  parts.push(header);
  parts.push(textBytes);
  parts.push(new Uint8Array([nPub]));

  // VK: alpha(96) + beta(192) + gamma(192) + delta(192) + IC[0..n](96 each)
  parts.push(g1ToBytes(vkey.vk_alpha_1 as string[]));
  parts.push(g2ToBytes(vkey.vk_beta_2 as string[][]));
  parts.push(g2ToBytes(vkey.vk_gamma_2 as string[][]));
  parts.push(g2ToBytes(vkey.vk_delta_2 as string[][]));
  for (const ic of vkey.IC as string[][]) parts.push(g1ToBytes(ic));

  // Proof: A(96) + B(192) + C(96)
  parts.push(g1ToBytes(proof.pi_a));
  parts.push(g2ToBytes(proof.pi_b));
  parts.push(g1ToBytes(proof.pi_c));

  // Public signals: 32 bytes each
  for (const sig of publicSignals) {
    const buf = new Uint8Array(32);
    bigintToBE(BigInt(sig), 32, buf, 0);
    parts.push(buf);
  }

  // Concat and hex-encode
  const total = parts.reduce((s, p) => s + p.length, 0);
  const result = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { result.set(p, off); off += p.length; }
  return Array.from(result).map(b => b.toString(16).padStart(2, "0")).join("");
}
import type {
  IntentSpec,
  Binding,
  EmittedTemplate,
  ResolvedHole,
  Value,
  Template,
  ResolvedAddress,
  ParamType,
} from "../clear-signing/engine/types";

// ─── Types ──────────────────────────────────────────────────────────────────

type Step =
  | { kind: "spec-match"; spec: IntentSpec | null; address: string; source?: "ens" | "static" }
  | { kind: "function-id"; binding: Binding | null; selector: string }
  | {
      kind: "calldata-decode";
      params: { name: string; type: ParamType; value: Value }[];
    }
  | {
      kind: "intent-eval";
      emitted: EmittedTemplate;
      allTemplates: Template[];
    }
  | {
      kind: "spec-resolution";
      resolutions: Map<string, ResolvedAddress | null>;
      pending: Set<string>;
    }
  | { kind: "verified-display"; text: string }
  | {
      kind: "proof";
      status: "pending" | "success" | "error" | "unavailable" | "hw-ready";
      result: ProofResult | null;
      hwVerified?: boolean;
      hwEchoedText?: string;
      error?: string;
      /** Circuit commitment verification against ENS */
      circuitCheck?: {
        ensHash: string | null;
        localHash: string | null;
        match: boolean;
      };
    };

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatValue(value: Value): string {
  switch (value.kind) {
    case "int":
      return value.value.toString();
    case "bool":
      return value.value ? "true" : "false";
    case "address":
      return value.value;
    case "list":
      return `[${value.items.map(formatValue).join(", ")}]`;
  }
}

function collectAddresses(holes: ResolvedHole[]): string[] {
  const addrs: string[] = [];
  for (const hole of holes) {
    if (hole.value.kind === "address") {
      addrs.push(hole.value.value);
    }
  }
  return addrs;
}

function renderIntent(
  emitted: EmittedTemplate,
  resolutions: Map<string, ResolvedAddress | null>
): string {
  let text = emitted.text;
  for (const hole of emitted.holes) {
    const placeholder = `{${hole.name}}`;
    let display: string;

    switch (hole.format.kind) {
      case "address": {
        const addr = hole.value.kind === "address" ? hole.value.value : "";
        const resolved = resolutions.get(addr.toLowerCase());
        display = formatAddress(addr, resolved);
        break;
      }
      case "tokenAmount": {
        const raw = hole.value.kind === "int" ? hole.value.value : 0n;
        display = formatTokenAmount(
          raw,
          hole.format.decimals,
          hole.format.symbol
        );
        break;
      }
      case "raw": {
        display = formatValue(hole.value);
        break;
      }
    }

    text = text.replaceAll(placeholder, display);
  }
  return text;
}

// ─── Lean DSL Sources ───────────────────���───────────────────────────────────
// Matches verity/Contracts/*/Display.lean from github.com/lfglabs-dev/verity

const LEAN_SOURCES: Record<string, string> = {
  USDC: `import Verity.Intent.DSL

namespace Contracts.USDC
open Verity.Intent.DSL

private def maxUint256 : Int := (2 ^ 256 : Nat) - 1

intent_spec "USDC" where
  const decimals := 6

  intent transfer(to : address, amount : uint256) where
    when amount == maxUint256 =>
      emit "Send all USDC to {to}"
    otherwise =>
      emit "Send {amount:fixed decimals} USDC to {to}"

  intent approve(spender : address, amount : uint256) where
    when amount == maxUint256 =>
      emit "Approve {spender} to spend unlimited USDC"
    otherwise =>
      emit "Approve {spender} to spend {amount:fixed decimals} USDC"

  intent transferFrom(from : address, to : address, amount : uint256) where
    when amount == maxUint256 =>
      emit "Transfer all USDC from {from} to {to}"
    otherwise =>
      emit "Transfer {amount:fixed decimals} USDC from {from} to {to}"

end Contracts.USDC`,

  UniswapV2Router: `import Verity.Intent.DSL

namespace Contracts.UniswapV2Router
open Verity.Intent.DSL

intent_spec "UniswapV2Router" where
  intent swapExactETHForTokens(amountOutMin : uint256, to : address) where
    emit "Swap ETH for at least {amountOutMin} {tokenOut}, send to {to}"

end Contracts.UniswapV2Router`,
};

// ─── DSL Syntax Highlighting ────────────────────────────────────────────────

function HighlightedDSL({ source }: { source: string }) {
  const lines = source.split("\n");
  return (
    <pre className="bg-surface border border-border rounded px-5 py-4 text-sm font-mono leading-relaxed overflow-x-auto">
      {lines.map((line, i) => (
        <div key={i}>{highlightLine(line)}</div>
      ))}
    </pre>
  );
}

function highlightLine(line: string): React.ReactNode {
  if (line.trim() === "") return "\u00A0";

  const tokens: React.ReactNode[] = [];
  let rest = line;
  let key = 0;

  const keywords = /^(\s*)(import|namespace|open|private|def|end|intent_spec|intent|const|predicate|when|otherwise|emit|bind|where)\b/;
  const match = rest.match(keywords);
  if (match) {
    tokens.push(match[1]); // leading whitespace
    tokens.push(
      <span key={key++} className="text-[#8B5CF6]">
        {match[2]}
      </span>
    );
    rest = rest.slice(match[0].length);
  }

  // Process remaining text token by token
  while (rest.length > 0) {
    // String literals
    const strMatch = rest.match(/^"([^"]*)"/);
    if (strMatch) {
      tokens.push(
        <span key={key++} className="text-[#059669]">
          &quot;{strMatch[1]}&quot;
        </span>
      );
      rest = rest.slice(strMatch[0].length);
      continue;
    }

    // Type annotations after colon
    const typeMatch = rest.match(
      /^(: )(uint256|address|uint256\[\]|address\[\]|bool|Int|Nat)\b/
    );
    if (typeMatch) {
      tokens.push(typeMatch[1]);
      tokens.push(
        <span key={key++} className="text-[#D97706]">
          {typeMatch[2]}
        </span>
      );
      rest = rest.slice(typeMatch[0].length);
      continue;
    }

    // Operators
    const opMatch = rest.match(/^(:=|=>|==|\^)/);
    if (opMatch) {
      tokens.push(
        <span key={key++} className="text-secondary">
          {opMatch[1]}
        </span>
      );
      rest = rest.slice(opMatch[0].length);
      continue;
    }

    // Numbers
    const numMatch = rest.match(/^\b(\d+)\b/);
    if (numMatch) {
      tokens.push(
        <span key={key++} className="text-[#2563EB]">
          {numMatch[1]}
        </span>
      );
      rest = rest.slice(numMatch[0].length);
      continue;
    }

    // Default: consume one character
    tokens.push(rest[0]);
    rest = rest.slice(1);
  }

  return <>{tokens}</>;
}

const SPEC_SOURCES = [
  { name: "USDC", file: "Contracts/USDC/Display.lean" },
  { name: "UniswapV2Router", file: "Contracts/UniswapV2Router/Display.lean" },
];

function SpecsLibrary() {
  const [selected, setSelected] = useState(0);
  const { name, file } = SPEC_SOURCES[selected];

  return (
    <Disclosure title="Specs library" className="mb-16">
      <div className="flex gap-2 mb-4">
        {SPEC_SOURCES.map((s, i) => (
          <button
            key={s.name}
            onClick={() => setSelected(i)}
            className={`px-3 py-1.5 text-[13px] font-mono border rounded transition-colors cursor-pointer ${
              i === selected
                ? "border-primary bg-primary/5 font-medium"
                : "border-border hover:bg-surface"
            }`}
          >
            {s.name}
          </button>
        ))}
      </div>
      <p className="text-secondary text-[12px] font-mono mb-3">
        {file}
      </p>
      <HighlightedDSL key={name} source={LEAN_SOURCES[name]} />
    </Disclosure>
  );
}

// ─── Step Components ────────────────────────────────────────────────────────

function StepContainer({
  index,
  title,
  status,
  children,
}: {
  index: number;
  title: string;
  status: "success" | "error" | "pending";
  children: React.ReactNode;
}) {
  const icon =
    status === "success" ? (
      <span className="text-emerald-600">&#10003;</span>
    ) : status === "error" ? (
      <span className="text-red-500">&#10007;</span>
    ) : (
      <span className="text-secondary animate-pulse">...</span>
    );

  return (
    <div className="mb-6 last:mb-0">
      <div className="flex items-center gap-2 mb-2">
        <span className="font-mono text-xs text-secondary">
          {index.toString().padStart(2, "0")}
        </span>
        <span className="text-[15px] font-medium">{title}</span>
        {icon}
      </div>
      <div className="ml-7 text-[14px] leading-relaxed">{children}</div>
    </div>
  );
}

function SpecMatchStep({
  step,
  spec,
}: {
  step: Extract<Step, { kind: "spec-match" }>;
  spec: IntentSpec | null;
}) {
  return (
    <StepContainer
      index={1}
      title="Spec lookup"
      status={step.spec ? "success" : "error"}
    >
      {step.spec ? (
        <>
          <p>
            Contract{" "}
            <span className="font-mono text-[13px]">
              {step.address.slice(0, 6)}...{step.address.slice(-4)}
            </span>{" "}
            matches{" "}
            <strong className="font-semibold">{step.spec.contractName}</strong>{" "}
            spec{" "}
            <span className={`text-[12px] font-mono ${
              step.source === "ens" ? "text-emerald-600" : "text-amber-500"
            }`}>
              ({step.source === "ens" ? "from veryclear.eth" : "static fallback"})
            </span>
          </p>
          {spec && LEAN_SOURCES[spec.contractName] && (
            <details className="mt-2">
              <summary className="text-[13px] text-secondary cursor-pointer select-none hover:text-foreground transition-colors">
                View spec definition
              </summary>
              <div className="mt-2 text-[12px]">
                <HighlightedDSL source={LEAN_SOURCES[spec.contractName]} />
              </div>
            </details>
          )}
          <details className="mt-2">
            <summary className="text-[13px] text-emerald-600 cursor-pointer select-none hover:text-emerald-700 transition-colors">
              View trust assumption (spec registry)
            </summary>
            <p className="mt-2 text-[13px] leading-relaxed text-emerald-600">
              This lookup queries{" "}
              <span className="font-mono">veryclear.eth</span> on Ethereum
              mainnet, an ENS-based registry managed by the Verity team. Each
              text record maps a contract address to a spec identifier,
              providing a verifiable on-chain source of truth. Alternatively,
              wallets could maintain their own registry with specs approved by
              the hardware wallet, establishing a full chain of trust from spec
              author to display device.
            </p>
          </details>
        </>
      ) : (
        <p className="text-red-600">
          No spec found for{" "}
          <span className="font-mono text-[13px]">{step.address}</span>
        </p>
      )}
    </StepContainer>
  );
}

function FunctionIdStep({
  step,
}: {
  step: Extract<Step, { kind: "function-id" }>;
}) {
  return (
    <StepContainer
      index={2}
      title="Function identification"
      status={step.binding ? "success" : "error"}
    >
      {step.binding ? (
        <p>
          Selector{" "}
          <span className="font-mono text-[13px]">{step.selector}</span>
          {" \u2192 "}
          <span className="font-mono text-[13px]">
            {step.binding.abiSignature}
          </span>
        </p>
      ) : (
        <p className="text-red-600">
          Unknown selector{" "}
          <span className="font-mono text-[13px]">{step.selector}</span>
        </p>
      )}
    </StepContainer>
  );
}

function CalldataDecodeStep({
  step,
}: {
  step: Extract<Step, { kind: "calldata-decode" }>;
}) {
  return (
    <StepContainer index={3} title="Calldata decoding" status="success">
      <div className="bg-surface border border-border rounded px-4 py-3 font-mono text-[13px] space-y-1">
        {step.params.map((p) => (
          <div key={p.name} className="flex gap-2">
            <span className="text-secondary min-w-[110px]">
              {p.name}
              <span className="text-secondary/60"> ({p.type})</span>
            </span>
            <span className="break-all">{formatValue(p.value)}</span>
          </div>
        ))}
      </div>
    </StepContainer>
  );
}

function IntentEvalStep({
  step,
}: {
  step: Extract<Step, { kind: "intent-eval" }>;
}) {
  return (
    <StepContainer index={4} title="Intent evaluation" status="success">
      <div className="space-y-2">
        {step.allTemplates.map((t, i) => {
          const isActive = i === step.emitted.templateIndex;
          return (
            <div
              key={i}
              className={`px-3 py-2 rounded border text-[13px] font-mono ${
                isActive
                  ? "border-emerald-300 bg-emerald-50 text-emerald-800"
                  : "border-border bg-white text-secondary line-through"
              }`}
            >
              <span className="text-secondary/60">
                #{i} {isActive ? "(active)" : "(skipped)"}
              </span>
              <div className="mt-0.5">{t.text}</div>
            </div>
          );
        })}
      </div>
    </StepContainer>
  );
}

function SpecResolutionStep({
  step,
}: {
  step: Extract<Step, { kind: "spec-resolution" }>;
}) {
  const entries = Array.from(step.resolutions.entries());
  if (entries.length === 0) {
    return (
      <StepContainer index={5} title="External specifications resolution" status="success">
        <p className="text-secondary">No external specs to resolve</p>
      </StepContainer>
    );
  }

  const allDone = step.pending.size === 0;

  return (
    <StepContainer
      index={5}
      title="External specifications resolution"
      status={allDone ? "success" : "pending"}
    >
      <div className="space-y-1.5">
        {entries.map(([addr, resolved]) => {
          const isPending = step.pending.has(addr);
          return (
            <div
              key={addr}
              className="flex items-center gap-2 font-mono text-[13px]"
            >
              <span className="text-secondary">
                {addr.slice(0, 6)}...{addr.slice(-4)}
              </span>
              <span className="text-secondary">{"\u2192"}</span>
              {isPending ? (
                <span className="text-secondary animate-pulse">
                  looking up spec...
                </span>
              ) : resolved ? (
                <span className="text-emerald-700 font-semibold">
                  {resolved.name}
                </span>
              ) : (
                <span className="text-amber-600">no spec</span>
              )}
            </div>
          );
        })}
      </div>
    </StepContainer>
  );
}

function VerifiedDisplayStep({
  step,
}: {
  step: Extract<Step, { kind: "verified-display" }>;
}) {
  return (
    <StepContainer index={6} title="Verified display" status="success">
      <div className="border-2 border-emerald-300 bg-emerald-50 rounded-lg px-5 py-4">
        <div className="flex items-start gap-2">
          <span className="text-emerald-600 text-lg leading-none mt-0.5">
            &#10003;
          </span>
          <p className="text-[16px] font-medium text-emerald-900 leading-snug">
            {step.text}
          </p>
        </div>
      </div>
    </StepContainer>
  );
}

function ProofStep({
  step,
  onVerifyHw,
  hwStatus,
}: {
  step: Extract<Step, { kind: "proof" }>;
  onVerifyHw: () => void;
  hwStatus: string | null;
}) {
  if (step.status === "unavailable") {
    return (
      <StepContainer index={7} title="Proof verification" status="error">
        <p className="text-secondary text-[13px]">
          No compiled circuit available for this function
        </p>
      </StepContainer>
    );
  }

  if (step.status === "pending") {
    return (
      <StepContainer index={7} title="Proof verification" status="pending">
        <p className="text-secondary text-[13px]">
          Computing Poseidon commitments and generating Groth16 proof...
        </p>
      </StepContainer>
    );
  }

  if (step.status === "error") {
    return (
      <StepContainer index={7} title="Proof verification" status="error">
        <p className="text-red-600 text-[13px]">{step.error}</p>
      </StepContainer>
    );
  }

  if (!step.result) {
    return (
      <StepContainer index={7} title="Proof verification" status="pending">
        <p className="text-secondary text-[13px]">Preparing proof data...</p>
      </StepContainer>
    );
  }
  const r = step.result!;
  return (
    <StepContainer index={7} title="Proof verification" status={r.verified ? "success" : "error"}>
      <div className="space-y-4">
        <details className="group/proof">
          <summary className="text-[13px] text-secondary cursor-pointer select-none hover:text-foreground transition-colors flex items-center gap-1.5">
            <svg
              viewBox="0 0 24 24"
              className="w-3.5 h-3.5 transition-transform group-open/proof:rotate-90"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <polyline points="9 18 15 12 9 6" />
            </svg>
            Proof details
          </summary>
          <div className="mt-3 space-y-4">
            {/* Circuit inputs */}
            <div>
              <p className="text-[13px] font-medium text-secondary mb-2">
                Circuit inputs
              </p>
              <div className="bg-surface border border-border rounded px-4 py-3 font-mono text-[12px] space-y-2">
                <div>
                  <div className="text-[11px] text-emerald-600 mb-1">Public input</div>
                  <div className="flex gap-2 ml-2">
                    <span className="text-secondary min-w-[100px]">selector</span>
                    <span className="break-all">{r.calldataInputs[0]?.value}</span>
                  </div>
                </div>
                <div>
                  <div className="text-[11px] text-amber-600 mb-1">Private inputs (hidden from verifier)</div>
                  <div className="space-y-0.5 ml-2">
                    {r.calldataInputs.slice(1).map((input) => (
                      <div key={input.name} className="flex gap-2">
                        <span className="text-secondary min-w-[100px]">{input.name}</span>
                        <span className="break-all">{input.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              <p className="text-[12px] text-secondary/70 mt-1.5">
                The prover knows all inputs. The verifier only sees the selector.
                uint256 values are split into two 128-bit limbs to fit BLS12-381.
              </p>
            </div>

            {/* Circuit outputs (Poseidon commitments) */}
            <div>
              <p className="text-[13px] font-medium text-secondary mb-2">
                Circuit outputs (computed by Poseidon inside the circuit)
              </p>
              <div className="bg-surface border border-border rounded px-4 py-3 font-mono text-[12px] space-y-3">
                <div>
                  <div className="text-secondary text-[11px] mb-0.5">
                    calldataCommitment = Poseidon({r.calldataInputs.map((i) => i.name).join(", ")})
                  </div>
                  <span className="break-all text-[11px]">{r.calldataCommitment}</span>
                </div>
                <div>
                  <div className="text-secondary text-[11px] mb-0.5">
                    outputCommitment = Poseidon({r.outputInputs.map((i) => i.name).join(", ")})
                  </div>
                  <span className="break-all text-[11px]">{r.outputCommitment}</span>
                </div>
              </div>
              <p className="text-[12px] text-secondary/70 mt-1.5">
                The circuit hashes the inputs with Poseidon over BLS12-381 and
                exposes these two commitments as public outputs. They bind the
                raw calldata and the evaluated template to the proof.
              </p>
            </div>

            {/* Proof */}
            <div>
              <p className="text-[13px] font-medium text-secondary mb-2">
                Groth16 proof (BLS12-381)
              </p>
              <div className="bg-surface border border-border rounded px-4 py-3 font-mono text-[11px] space-y-2">
                <div>
                  <span className="text-[#8B5CF6]">{"\u03C0_A"}</span>
                  <span className="text-secondary"> (G1): </span>
                  <span className="break-all text-secondary/80">
                    [{r.proof.pi_a[0].slice(0, 20)}...]
                  </span>
                </div>
                <div>
                  <span className="text-[#8B5CF6]">{"\u03C0_B"}</span>
                  <span className="text-secondary"> (G2): </span>
                  <span className="break-all text-secondary/80">
                    [[{r.proof.pi_b[0][0].slice(0, 12)}...], [{r.proof.pi_b[1][0].slice(0, 12)}...]]
                  </span>
                </div>
                <div>
                  <span className="text-[#8B5CF6]">{"\u03C0_C"}</span>
                  <span className="text-secondary"> (G1): </span>
                  <span className="break-all text-secondary/80">
                    [{r.proof.pi_c[0].slice(0, 20)}...]
                  </span>
                </div>
              </div>
              <p className="text-[12px] text-secondary/70 mt-1.5">
                Three elliptic curve points proving the prover knows private
                inputs that satisfy all circuit constraints without revealing them.
              </p>
            </div>
          </div>
        </details>

        {/* Verification result */}
        <div
          className={`px-4 py-3 rounded-lg border-2 ${
            r.verified
              ? "border-emerald-300 bg-emerald-50"
              : "border-red-300 bg-red-50"
          }`}
        >
          <div className="flex items-center gap-2">
            <span
              className={`text-lg ${r.verified ? "text-emerald-600" : "text-red-500"}`}
            >
              {r.verified ? "\u2713" : "\u2717"}
            </span>
            <span
              className={`text-[14px] font-medium font-mono ${
                r.verified ? "text-emerald-900" : "text-red-900"
              }`}
            >
              {r.verified
                ? "e(\u03C0\u2090, \u03C0\u1D47) = e(\u03B1, \u03B2) \u00B7 e(L, \u03B3) \u00B7 e(\u03C0\u1D9C, \u03B4)"
                : "Verification failed"}
            </span>
          </div>
          <p
            className={`text-[12px] mt-1 ml-7 ${
              r.verified ? "text-emerald-700/70" : "text-red-700/70"
            }`}
          >
            {r.verified ? "Pairing check passed" : "Pairing check failed"}
            {", "}generated in {r.proveTimeMs.toFixed(0)}ms, verified in{" "}
            {r.verifyTimeMs.toFixed(0)}ms
          </p>
        </div>

        {/* Hardware verification */}
        {r.verified && !step.hwVerified && (
          <div className="mt-4">
            <button
              onClick={onVerifyHw}
              className="w-full py-3 px-4 rounded-lg font-semibold text-base bg-black text-white hover:bg-gray-800 active:scale-[0.98] transition-all cursor-pointer"
            >
              &#x1f50f; Verify on Ledger Nano S+
            </button>
            {hwStatus && (
              <p className="text-[12px] font-mono text-secondary mt-2 text-center">{hwStatus}</p>
            )}
          </div>
        )}
        {step.hwVerified !== undefined && (
          <div className={`mt-4 px-4 py-3 rounded-lg border-2 ${
            step.hwVerified ? "border-emerald-300 bg-emerald-50" : "border-red-300 bg-red-50"
          }`}>
            <div className="flex items-center gap-2">
              <span className={`text-lg ${step.hwVerified ? "text-emerald-600" : "text-red-500"}`}>
                {step.hwVerified ? "\u2713" : "\u2717"}
              </span>
              <span className={`text-[14px] font-medium font-mono ${
                step.hwVerified ? "text-emerald-900" : "text-red-900"
              }`}>
                {step.hwVerified
                  ? "Groth16 proof verified on Ledger Nano S+"
                  : "Hardware verification failed"}
              </span>
            </div>
            {step.hwEchoedText && (
              <p className="text-[12px] mt-2 ml-7 text-emerald-700/70 font-mono">
                Device confirmed: \u201c{step.hwEchoedText}\u201d
              </p>
            )}
            <p className="text-[12px] mt-1 ml-7 text-secondary">
              BLS12-381 \u00b7 Groth16 \u00b7 4-pairing batch \u00b7 ARM Cortex-M35P
            </p>
          </div>
        )}

        {step.circuitCheck && (
          <div className={`px-4 py-3 rounded-lg border ${
            step.circuitCheck.match
              ? "border-emerald-200 bg-emerald-50"
              : "border-amber-200 bg-amber-50"
          }`}>
            <p className={`text-[13px] font-medium ${
              step.circuitCheck.match ? "text-emerald-800" : "text-amber-800"
            }`}>
              {step.circuitCheck.match
                ? "Circuit commitment matches ENS registry"
                : "Circuit commitment not found in ENS registry"}
            </p>
            <div className="mt-1.5 font-mono text-[11px] space-y-0.5">
              <div className="flex gap-2">
                <span className={step.circuitCheck.match ? "text-emerald-600" : "text-amber-600"}>
                  vkey hash:
                </span>
                <span className="break-all text-secondary">
                  {step.circuitCheck.localHash?.slice(0, 16)}...
                </span>
              </div>
              {step.circuitCheck.ensHash && (
                <div className="flex gap-2">
                  <span className={step.circuitCheck.match ? "text-emerald-600" : "text-amber-600"}>
                    ENS record:
                  </span>
                  <span className="break-all text-secondary">
                    {step.circuitCheck.ensHash.slice(0, 16)}...
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        <details>
          <summary className="text-[13px] text-amber-600 cursor-pointer select-none hover:text-amber-700 transition-colors">
            View trust assumption
          </summary>
          <p className="mt-2 text-[13px] leading-relaxed text-amber-600">
            This proof only guarantees that the displayed template is correct
            according to the specification the circuit was compiled from. The
            natural language string itself is not inside the proof. For the
            display to be trustworthy, the spec must come from the trusted
            registry described in step 1.
          </p>
        </details>
      </div>
    </StepContainer>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function ClearSigningPage() {
  const contractAddress = DEMO_EXAMPLE.contractAddress;
  const calldata = DEMO_EXAMPLE.calldata;
  const [steps, setSteps] = useState<Step[]>([]);
  const [activeSpec, setActiveSpec] = useState<IntentSpec | null>(null);
  const abortRef = useRef(false);
  const hwTextRef = useRef<string>("");
  const hwVkeyRef = useRef<Record<string, unknown> | null>(null);
  const hwProofRef = useRef<{ pi_a: string[]; pi_b: string[][]; pi_c: string[] } | null>(null);
  const hwPubRef = useRef<string[]>([]);
  const [ledger, setLedger] = useState<LedgerDevice | null>(null);
  const [hwStatus, setHwStatus] = useState<string | null>(null);

  const interpret = useCallback(async () => {
    if (!contractAddress || !calldata) return;
    abortRef.current = false;

    setSteps([]);
    setActiveSpec(null);

    const addStep = (step: Step) => {
      if (abortRef.current) return;
      setSteps((prev) => [...prev, step]);
    };

    const delay = (ms: number) =>
      new Promise<void>((resolve) => setTimeout(resolve, ms));

    // We'll need these across steps
    let spec: IntentSpec | null = null;
    let binding: Binding | null = null;
    let params: Map<string, Value> = new Map();
    let emitted: EmittedTemplate | null = null;
    let addresses: string[] = [];

    try {
      // Step 1: Spec lookup
      await delay(300);
      const lookup = await findSpecFromEns(contractAddress);
      spec = lookup?.spec ?? null;
      addStep({ kind: "spec-match", spec, address: contractAddress, source: lookup?.source });
      if (spec) setActiveSpec(spec);
      if (!spec) {
        return;
      }

      // Step 2: Function identification
      await delay(400);
      const selector = extractSelector(calldata);
      binding =
        spec.bindings.find(
          (b) => b.selector.toLowerCase() === selector.toLowerCase()
        ) ?? null;
      addStep({ kind: "function-id", binding, selector });
      if (!binding) {

        return;
      }

      // Step 3: Calldata decoding
      await delay(400);
      const intentFn = spec.fns.find(
        (f) => f.name === binding!.intentFnName
      );
      if (!intentFn) {

        return;
      }
      params = decodeCalldata(calldata, intentFn, binding.paramMapping);
      const paramsList = Array.from(params.entries()).map(([name, value]) => ({
        name,
        type:
          intentFn.params.find((p) => p.name === name)?.type ??
          ("uint256" as ParamType),
        value,
      }));
      addStep({ kind: "calldata-decode", params: paramsList });

      // Step 4: Intent evaluation
      await delay(500);
      emitted = evaluateIntent(spec, binding, params);
      if (!emitted) {

        return;
      }
      const allTemplates = collectAllTemplates(intentFn.body);
      addStep({ kind: "intent-eval", emitted, allTemplates });

      // Step 5: External specifications resolution (progressive)
      addresses = collectAddresses(emitted.holes);
      if (addresses.length > 0) {
        await delay(300);
        const resolutions = new Map<string, ResolvedAddress | null>();
        const pending = new Set(addresses.map((a) => a.toLowerCase()));
        for (const addr of addresses) {
          resolutions.set(addr.toLowerCase(), null);
        }
        addStep({ kind: "spec-resolution", resolutions, pending });

        for (const addr of addresses) {
          if (abortRef.current) break;
          const resolved = await resolveAddressAsync(
            addr,
            500 + Math.random() * 400
          );
          const newResolutions = new Map(resolutions);
          newResolutions.set(addr.toLowerCase(), resolved);
          resolutions.set(addr.toLowerCase(), resolved);
          const newPending = new Set(pending);
          newPending.delete(addr.toLowerCase());
          pending.delete(addr.toLowerCase());
          setSteps((prev) => {
            const updated = [...prev];
            const idx = updated.findIndex(
              (s) => s.kind === "spec-resolution"
            );
            if (idx >= 0) {
              updated[idx] = {
                kind: "spec-resolution",
                resolutions: new Map(newResolutions),
                pending: new Set(newPending),
              };
            }
            return updated;
          });
        }
      }

      // Step 6: Verified display
      await delay(400);
      const finalResolutions = new Map<string, ResolvedAddress | null>();
      for (const addr of addresses) {
        const { resolveAddress } = await import("../clear-signing/engine/resolver");
        finalResolutions.set(addr.toLowerCase(), resolveAddress(addr));
      }
      const finalText = renderIntent(emitted, finalResolutions);
      addStep({ kind: "verified-display", text: finalText });

      // Step 7: Proof generation & verification
      if (!hasCircuit(spec.contractName, binding.intentFnName)) {
        addStep({
          kind: "proof",
          status: "unavailable",
          result: null,
        });
      } else {
        addStep({ kind: "proof", status: "pending", result: null });

        try {
          const result = await generateAndVerifyProof(
            spec.contractName,
            binding,
            params,
            emitted
          );
          // Store for hardware verification
          hwTextRef.current = finalText;
          hwProofRef.current = result.proof;
          hwPubRef.current = result.publicSignals;
          // Fetch VK for hardware serialization
          const circuitName = spec.contractName === "ERC20" ? `ERC20_${binding.intentFnName}` : null;
          if (circuitName) {
            const vkResp = await fetch(`/circuits/${circuitName}/vkey.json`);
            hwVkeyRef.current = await vkResp.json();
          }

          // Verify circuit commitment against ENS registry
          let circuitCheck: { ensHash: string | null; localHash: string | null; match: boolean } | undefined;
          const localHash = await getVkeyHash(spec.contractName, binding.intentFnName);
          if (lookup?.ensEntry?.circuits && localHash) {
            const ensHash = lookup.ensEntry.circuits[binding.intentFnName] ?? null;
            circuitCheck = {
              ensHash,
              localHash,
              match: ensHash === localHash,
            };
          }

          setSteps((prev) => {
            const updated = [...prev];
            const idx = updated.findIndex((s) => s.kind === "proof");
            if (idx >= 0) {
              updated[idx] = { kind: "proof", status: "success", result, circuitCheck };
            }
            return updated;
          });
        } catch (e) {
          setSteps((prev) => {
            const updated = [...prev];
            const idx = updated.findIndex((s) => s.kind === "proof");
            if (idx >= 0) {
              updated[idx] = {
                kind: "proof",
                status: "error",
                result: null,
                error: e instanceof Error ? e.message : String(e),
              };
            }
            return updated;
          });
        }
      }
    } catch (e) {
      console.error("Interpretation error:", e);
    } finally {
      // done
    }
  }, [contractAddress, calldata]);

  // Auto-run whenever inputs change
  useEffect(() => {
    if (!calldata || !contractAddress) return;
    const timer = setTimeout(() => interpret(), 150);
    return () => clearTimeout(timer);
  }, [calldata, contractAddress, interpret]);

  const verifyOnHardware = useCallback(async () => {
    setHwStatus("connecting");
    try {
      let dev = ledger;
      if (!dev) { dev = await connectLedger(); setLedger(dev); }
      setHwStatus("building payload");
      const text = hwTextRef.current;
      const vkey = hwVkeyRef.current;
      const proof = hwProofRef.current;
      const pub = hwPubRef.current;
      if (!text || !vkey || !proof || !pub.length) throw new Error("No proof data");
      const payloadHex = buildClearSignPayload(text, vkey, proof, pub);
      const chunks = buildChunkedAPDUs(INS_CLEAR_SIGN, payloadHex);
      setHwStatus(`sending ${chunks.length} chunks (${payloadHex.length/2} bytes)`);
      const result = await sendChunkedAPDUs(dev, chunks, (i, total) => {
        setHwStatus(`chunk ${i + 1}/${total}`);
      });
      const ok = result.sw === 0x9000 && result.data[0] === 0x01;
      const echo = new TextDecoder().decode(result.data.slice(1));
      setSteps((prev) => {
        const updated = [...prev];
        const idx = updated.findIndex((s) => s.kind === "proof");
        if (idx >= 0) {
          const existing = updated[idx] as Extract<Step, { kind: "proof" }>;
          updated[idx] = { ...existing, hwVerified: ok, hwEchoedText: echo };
        }
        return updated;
      });
      setHwStatus(ok ? "verified" : "failed");
    } catch (e) {
      setHwStatus("error: " + (e instanceof Error ? e.message : String(e)));
    }
  }, [ledger]);

  return (
    <main className="font-serif max-w-[680px] mx-auto px-6 py-20 md:py-32">
      <header className="mb-16">
        <h1 className="text-3xl md:text-4xl font-semibold tracking-tight leading-tight">
          Clear Signing
        </h1>
        <p className="mt-3 text-secondary text-base leading-relaxed">
          Natural language interpretation of transaction intent, backed by
          zero-knowledge proofs.
        </p>
      </header>

      <section className="mb-16 leading-relaxed space-y-4">
        <p>
          When you sign an Ethereum transaction, your wallet shows you raw
          calldata, a hex blob that means nothing to a human. Clear signing
          translates this intent into natural language. But that translation is
          a new thing to trust. We propose an extension of the Verity DSL
          allowing to formalize natural language interpretation of user intents
          within the protocol specifications.
        </p>
        <p>
          The compiler produces two artifacts from each{" "}
          <ExternalLink href="https://github.com/lfglabs-dev/verity/pull/1677">
            spec
          </ExternalLink>
          : a JSON descriptor that any frontend can load to interpret calldata
          as natural language, and a Groth16 circuit that allows even an
          embedded device to verify the interpretation is correct.
        </p>
      </section>

      <Disclosure title="How it works" className="mb-3">
        <ol className="list-decimal list-inside space-y-2 text-[15px] leading-relaxed">
          <li>
            <strong className="font-medium">Spec lookup</strong>: the
            contract address is looked up in the specs library
          </li>
          <li>
            <strong className="font-medium">Function identification</strong>:
            the 4-byte selector identifies which function is being called
          </li>
          <li>
            <strong className="font-medium">Calldata decoding</strong>: raw
            bytes are decoded into typed parameters using the ABI
          </li>
          <li>
            <strong className="font-medium">Intent evaluation</strong>: the
            DSL program selects a template and fills its holes
          </li>
          <li>
            <strong className="font-medium">External specifications resolution</strong>:
            addresses in the template are matched against other specs in the registry
          </li>
          <li>
            <strong className="font-medium">Verified display</strong>: the
            final sentence is shown
          </li>
          <li>
            <strong className="font-medium">Proof generation</strong>: a
            Groth16 proof is generated and verified in your browser
          </li>
        </ol>
      </Disclosure>

      <SpecsLibrary />

      <section className="mb-16">
        <h2 className="text-lg font-semibold tracking-tight mb-2">
          Demo
        </h2>
        <p className="text-secondary text-[15px] leading-relaxed mb-6">
          {DEMO_EXAMPLE.description}: interpreting raw calldata through the
          full pipeline, from spec lookup to Groth16 proof verification.
        </p>

        {steps.length > 0 && (
          <div className="border border-border rounded-lg px-6 py-5">
            {steps.map((step, i) => {
              switch (step.kind) {
                case "spec-match":
                  return (
                    <SpecMatchStep key={i} step={step} spec={activeSpec} />
                  );
                case "function-id":
                  return <FunctionIdStep key={i} step={step} />;
                case "calldata-decode":
                  return <CalldataDecodeStep key={i} step={step} />;
                case "intent-eval":
                  return <IntentEvalStep key={i} step={step} />;
                case "spec-resolution":
                  return <SpecResolutionStep key={i} step={step} />;
                case "verified-display":
                  return <VerifiedDisplayStep key={i} step={step} />;
                case "proof":
                  return <ProofStep key={i} step={step} onVerifyHw={verifyOnHardware} hwStatus={hwStatus} />;
              }
            })}
          </div>
        )}
      </section>

      <footer className="mt-12 pt-8 border-t border-border">
        <p className="text-secondary text-sm">
          Part of the{" "}
          <ExternalLink href="https://verity.labs">Verity</ExternalLink>{" "}
          benchmark initiative.{" "}
          <ExternalLink href="https://github.com/lfglabs-dev/verity/pull/1677">
            View the Provable Intent DSL
          </ExternalLink>
        </p>
      </footer>
    </main>
  );
}
