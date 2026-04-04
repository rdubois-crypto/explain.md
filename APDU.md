# APDU Protocol — ZK Clear Signing

## Transport

All APDUs use chunked transfer for large payloads:

```
CLA = 0xE0
P1  = chunk index (0, 1, 2, ...)
P2  = 0x80 (more chunks) or 0x00 (last chunk)
Lc  = chunk length (max 250 bytes)
```

The device accumulates chunks in a global buffer and processes on the last chunk (P2=0x00).

---

## INS 0x63 — CLEAR_SIGN

Display a human-readable transaction intent on the Nano screen, ask for user confirmation, then verify the Groth16 proof that this intent was correctly derived from the calldata.

### Request payload

```
┌──────────────┬──────────────────────────────────────────────────┐
│ Offset       │ Field                                            │
├──────────────┼──────────────────────────────────────────────────┤
│ 0            │ text_len (2 bytes, big-endian)                   │
│ 2            │ text (UTF-8, text_len bytes)                     │
│ 2+text_len   │ nPublic (1 byte)                                 │
│              │ VK_alpha (96 bytes — G1 point, x‖y)             │
│              │ VK_beta (192 bytes — G2 point, x0‖x1‖y0‖y1)    │
│              │ VK_gamma (192 bytes — G2 point)                  │
│              │ VK_delta (192 bytes — G2 point)                  │
│              │ IC[0] (96 bytes — G1 point)                      │
│              │ IC[1] (96 bytes — G1 point)                      │
│              │ ... IC[nPublic] (96 bytes each)                  │
│              │ proof.A (96 bytes — G1 point)                    │
│              │ proof.B (192 bytes — G2 point)                   │
│              │ proof.C (96 bytes — G1 point)                    │
│              │ pub[0] (32 bytes — Fr scalar, big-endian)        │
│              │ ... pub[nPublic-1] (32 bytes each)               │
└──────────────┴──────────────────────────────────────────────────┘
```

**Typical size:** ~1400 bytes for nPublic=3 (6 chunks of 250 bytes)

### Point encoding

All elliptic curve points are uncompressed, big-endian, affine coordinates:

- **G1 (BLS12-381):** `x (48 bytes) ‖ y (48 bytes)` = 96 bytes
- **G2 (BLS12-381):** `x0 (48 bytes) ‖ x1 (48 bytes) ‖ y0 (48 bytes) ‖ y1 (48 bytes)` = 192 bytes

G2 uses the tower extension Fp2 = Fp[u]/(u²+1), with coordinates as (c0 + c1·u).

### Device behavior

1. **Parse** text and Groth16 data from chunked buffer
2. **Display** the intent text on screen via NBGL review flow:
   ```
   ┌─────────────────────────┐
   │  Review ZK Clear Sign   │
   │         ▶               │
   ├─────────────────────────┤
   │  Intent:                │
   │  Approve UniswapV2      │
   │  Router to spend        │
   │  unlimited USDC         │
   ├─────────────────────────┤
   │  ✓ Sign intent          │
   │  ✗ Reject               │
   └─────────────────────────┘
   ```
3. **On Approve:** verify Groth16 proof (4-pairing batch check), return result
4. **On Reject:** return SW=0x6985

### Groth16 verification

The device computes the pairing check:

```
e(A, B) · e(-vk_x, γ) · e(-C, δ) · e(-α, β) == 1

where vk_x = IC[0] + Σ pub[i] · IC[i+1]
```

This uses the Miller loop + final exponentiation over BLS12-381 (381-bit prime field, embedding degree 12).

### Response (on approve)

```
┌──────────┬───────────────────────────────────────┐
│ Byte 0   │ 0x01 = verified, 0x00 = proof invalid │
│ Byte 1.. │ text echo (text_len bytes, UTF-8)     │
│ SW       │ 0x9000                                 │
└──────────┴───────────────────────────────────────┘
```

The text echo allows the browser to confirm the Nano received the correct intent string.

### Response (on reject)

```
SW = 0x6985 (SW_DENY)
```

### Example (USDC Approve)

```
Text:     "Approve UniswapV2Router to spend unlimited USDC" (47 bytes)
nPublic:  3
Signals:  [calldataCommitment, outputCommitment, selector]
VK:       from /circuits/ERC20_approve/vkey.json (BLS12-381)
Proof:    from snarkjs.groth16.fullProve() in the browser

Payload:  002f 417070726f76652055...  (text)
          03                          (nPublic=3)
          0aae...                     (alpha, 96 bytes)
          ...                         (beta/gamma/delta/IC, 864 bytes)
          ...                         (proof A/B/C, 384 bytes)
          ...                         (3 × 32-byte public signals)
Total:    ~1400 bytes → 6 chunks
```

---

## INS 0x64 — VERIFY_VK_STORAGE

Verify an Ethereum Merkle Patricia Trie (MPT) storage proof that the VK hash is authentically stored on-chain in the ENS PublicResolver.

### Background

The VK hash is stored as an ENS text record:

```
ENS:   veryklear.eth
Key:   vkHash:ERC20_approve
Value: cd361ed5f2a52e4e4bb981b8c6b47a72679c3e367e5132e219929ad54cd877bb
```

This 64-character hex string is a Solidity "long string" (>31 bytes), stored across **2 consecutive storage slots** in the PublicResolver contract. The APDU proves both slots.

### Storage slot computation

The PublicResolver uses a versioned text mapping:

```solidity
mapping(uint64 => mapping(bytes32 => mapping(string => string))) versionable_texts;
// at base storage slot 10
```

Slot derivation for `versionable_texts[0][node][key]`:

```
s1 = keccak256(abi.encode(uint256(0), uint256(10)))           // version mapping
s2 = keccak256(abi.encode(node, s1))                           // node mapping
s3 = keccak256(bytes(key) ‖ s2)                                // string key mapping
dataSlot0 = keccak256(s3)                                      // long string data, first 32 bytes
dataSlot1 = keccak256(s3) + 1                                  // long string data, next 32 bytes
```

### Request payload

```
┌──────────────┬──────────────────────────────────────────────────┐
│ Offset       │ Field                                            │
├──────────────┼──────────────────────────────────────────────────┤
│ 0            │ storageHash (32 bytes)                            │
│ 32           │ nProofs (1 byte) — always 2 for long strings     │
│              │                                                   │
│              │ ── Proof 0 (first 32 bytes of string) ──         │
│ 33           │ slot_0 (32 bytes — dataSlot0)                    │
│ 65           │ nNodes_0 (1 byte)                                 │
│ 66           │ nodeLen_0 (2 bytes BE) ‖ nodeData_0 (RLP)        │
│              │ nodeLen_1 (2 bytes BE) ‖ nodeData_1 (RLP)        │
│              │ ... (nNodes_0 nodes)                              │
│              │                                                   │
│              │ ── Proof 1 (next 32 bytes of string) ──          │
│              │ slot_1 (32 bytes — dataSlot1)                    │
│              │ nNodes_1 (1 byte)                                 │
│              │ nodeLen_0 (2 bytes BE) ‖ nodeData_0 (RLP)        │
│              │ ... (nNodes_1 nodes)                              │
│              │                                                   │
│              │ expectedVkHash (32 bytes)                         │
└──────────────┴──────────────────────────────────────────────────┘
```

**Typical size:** ~2000-4000 bytes depending on trie depth (8-16 chunks)

### MPT verification algorithm

For each proof, the device:

1. Compute MPT key: `nibbles = keccak256(slot)` expanded to 64 nibbles
2. Set `expected_hash = storageHash`
3. For each RLP node in the proof:
   - Verify `keccak256(node) == expected_hash`
   - Decode RLP: branch (17 items) or extension/leaf (2 items)
   - **Branch:** follow the nibble at `key[pos]`, advance position
   - **Extension:** verify path prefix matches, advance position, follow hash
   - **Leaf:** verify remaining path matches, decode nested RLP value
4. Extract 32-byte value from leaf (RLP-decoded, zero-padded left)

### Value reconstruction

The two 32-byte values are the raw UTF-8 bytes of the hex string:

```
val0 = "cd361ed5f2a52e4e4bb981b8c6b47a72"  (32 ASCII chars = 32 bytes)
val1 = "679c3e367e5132e219929ad54cd877bb"  (32 ASCII chars = 32 bytes)
```

The device concatenates them (64 bytes), interprets as hex, and converts to the 32-byte hash:

```
hex_decode("cd361ed5...cd877bb") → 32 bytes
compare with expectedVkHash → match/mismatch
```

### Response

```
┌──────────┬───────────────────────────────────────────────┐
│ Byte 0   │ 0x01 = match, 0x00 = mismatch or proof error │
│ Byte 1-32│ extracted hash (32 bytes, from MPT)           │
│ SW       │ 0x9000                                        │
└──────────┴───────────────────────────────────────────────┘
```

### Error cases

The device returns `0x00` (mismatch) if:

- MPT hash chain is broken (`keccak256(node) != expected`)
- RLP decoding fails (malformed node)
- Nibble path diverges (wrong slot)
- Leaf not found in trie
- Leaf value is malformed (bad RLP nesting)
- Reconstructed hash ≠ expectedVkHash

### Security properties

| Property | Guarantee |
|---|---|
| **Storage inclusion** | The value exists at the proven slot in the contract's storage trie |
| **Data integrity** | Each MPT node is hash-linked (Keccak-256 chain from storageHash) |
| **Tamper detection** | Modifying the expected hash → the Nano reports mismatch |
| **Trust assumption** | The `storageHash` itself is trusted (from `eth_getProof` response) |

**Note:** Full trustlessness requires verifying `storageHash` via an account proof against a trusted state root (e.g., from a light client or beacon chain). This is not yet implemented.

---

## INS Summary

```
┌──────┬─────────────────────┬──────────────────────────────────────────┐
│ INS  │ Name                │ What it verifies                         │
├──────┼─────────────────────┼──────────────────────────────────────────┤
│ 0x60 │ GROTH16_VERIFY      │ Groth16 proof (hardcoded VK)             │
│ 0x61 │ PLONK_VERIFY        │ PLONK proof                              │
│ 0x62 │ PAIRING_TEST        │ BLS12-381 pairing engine self-test       │
│ 0x63 │ CLEAR_SIGN          │ Display intent + Groth16 (generic VK)    │
│ 0x64 │ VERIFY_VK_STORAGE   │ ENS storage proof (MPT + Keccak-256)     │
└──────┴─────────────────────┴──────────────────────────────────────────┘
```
