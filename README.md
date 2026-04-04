# ZK Clear Signing — Hardware-Verified Transaction Intents

End-to-end ZK clear signing with Groth16 proof verification and on-chain VK attestation on a Ledger Nano S+.

## What This Does

When you sign an Ethereum transaction, your wallet shows you raw calldata — unreadable hex. Clear signing translates this into human-readable intent: *"Approve UniswapV2Router to spend unlimited USDC"*. But how do you know this translation is correct?

This project proves it cryptographically:

1. A **Groth16 proof** (BLS12-381) attests that the human-readable intent was correctly derived from the raw calldata, using a formally verified DSL compiler (Verity)
2. The **Ledger Nano S+** verifies this proof on its secure element (ARM Cortex-M35P), so you don't trust the browser
3. An **Ethereum storage proof** (Merkle Patricia Trie) proves that the verification key is authentically stored in ENS, so the Nano doesn't trust the browser for the VK either

```
┌─────────────────────────────────────────────────────────────────┐
│                         Browser                                 │
│                                                                 │
│  Calldata ──→ Verity DSL eval ──→ "Approve UniswapV2Router..."  │
│                    │                                            │
│           snarkjs.groth16.fullProve()                           │
│                    │                                            │
│              BLS12-381 proof                                    │
│                    │                                            │
│   ┌────────────────┼────────────────────────────────────┐       │
│   │                ▼           Ledger Nano S+           │       │
│   │                                                     │       │
│   │  1. Verify VK storage proof (MPT + Keccak-256)     │       │
│   │     → VK hash matches ENS on-chain commitment      │       │
│   │                                                     │       │
│   │  2. Display intent: "Approve UniswapV2Router..."   │       │
│   │     → User confirms on device buttons              │       │
│   │                                                     │       │
│   │  3. Verify Groth16 proof (4 pairings BLS12-381)    │       │
│   │     → e(πₐ,πᵦ) = e(α,β)·e(L,γ)·e(πc,δ)          │       │
│   │                                                     │       │
│   │  4. Return result → ✓ verified                     │       │
│   └─────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

## Pages

| Route | Description |
|---|---|
| `/clear-signing` | Original demonstrator — Groth16 proof generated and verified in-browser |
| `/clear-signing-hw` | Same flow, but Step 7 sends the real BLS12-381 proof to the Ledger Nano S+ for hardware verification |
| `/verifyvk` | Standalone page — fetches VK hash from ENS, generates Ethereum storage proof, verifies on Nano |

## Architecture

### Circuit (BLS12-381)

The Groth16 circuit is compiled from Lean-generated Circom by the [Verity compiler](https://github.com/lfglabs-dev/verity). It proves:

- The function selector matches a known ABI function
- The DSL evaluator selects the correct human-readable template
- `Poseidon(selector, params...) == calldataCommitment` (binds to raw calldata)
- `Poseidon(templateId, params...) == outputCommitment` (binds to display string)

Poseidon is computed **inside the circuit** over BLS12-381's scalar field — no JS-side hash computation needed.

**Public signals (3):** `calldataCommitment`, `outputCommitment`, `selector`
**Circuit artifacts:** `public/circuits/ERC20_approve/` (`.wasm`, `.zkey`, `vkey.json`)

### Ledger Nano S+ APDUs

See [APDU.md](APDU.md) for the full protocol specification.

| INS | Name | Description |
|---|---|---|
| `0x60` | `GROTH16_VERIFY` | Hardcoded VK Groth16 verification |
| `0x61` | `PLONK_VERIFY` | PLONK verification |
| `0x62` | `PAIRING_TEST` | BLS12-381 pairing self-test |
| `0x63` | `CLEAR_SIGN` | Display intent + verify Groth16 proof |
| `0x64` | `VERIFY_VK_STORAGE` | Verify ENS storage proof of VK hash |

### WebHID Transport

The browser communicates with the Nano via WebHID (no npm dependencies). The transport is implemented in ~130 lines in `src/app/clear-signing-hw/ledger.ts` with raw HID framing (channel 0x0101, tag 0x05, 64-byte reports).

### ENS Registry

VK hashes are stored as text records on ENS:

```
ENS name: veryklear.eth
Key:      vkHash:ERC20_approve
Value:    cd361ed5f2a52e4e4bb981b8c6b47a72679c3e367e5132e219929ad54cd877bb
```

The value is `SHA-256(vkey.json)`. The storage proof verifies this value on-chain using `eth_getProof` and MPT traversal.

## Quick Start

### Frontend

```bash
npm install
npm run dev
# → http://localhost:3000/clear-signing-hw
# → http://localhost:3000/verifyvk
```

### Nano App

```bash
make clean && ./load.sh
```

### Test MPT locally

```bash
cd mpt_test
make   # fetches proof from Ethereum, compiles C verifier, runs test
```

## Trust Model

| Component | Trusts | Verifies |
|---|---|---|
| Browser | RPC provider, circuit artifacts | DSL evaluation, snarkjs proof gen |
| Nano (CLEAR_SIGN) | Nothing | Groth16 pairing check (4 pairings BLS12-381) |
| Nano (VERIFY_VK_STORAGE) | Block header (storageHash) | MPT proof chain (Keccak-256 at each node) |
| ENS | Ethereum consensus | N/A (data availability) |

**What's not yet verified on-device:** the `storageHash` itself should be verified via an account proof against a trusted state root. This requires either a light client or a trusted block header feed.

## Stack

- **Curves:** BLS12-381 (Groth16 circuit + verifier), BN254/BabyJubjub (EdDSA/FROST/Poseidon for other app features)
- **Proof system:** Groth16 (snarkjs in browser, custom C verifier on Nano)
- **Hash functions:** Poseidon (inside circuit, BLS12-381 field), Keccak-256 (MPT proofs), SHA-256 (VK commitment)
- **Frontend:** Next.js, TypeScript, WebHID
- **Nano SDK:** BOLOS (ARM Cortex-M35P), NBGL display framework
- **DSL:** Verity (Lean 4 → Circom)

## Credits

- [ZKNOX](https://zknox.com) — Post-quantum cryptography for Ethereum
- [LFG Labs / Verity](https://github.com/lfglabs-dev/verity) — Formally verified smart contract DSL
- Circuit compilation and clear signing architecture by Th0rgal (LFG Labs)
- Hardware implementation (BLS12-381 pairing, Groth16/PLONK verifier, MPT proof, Ledger Nano S+ integration) by [rdubois-crypto](https://github.com/rdubois-crypto)

## References

- [Unlimited public computation in constrained hardware using ZK proofs — Application to ZK clear signing](https://zknox.eth.limo/posts/2026/03/13/zk_clear_signing_160326.html)
