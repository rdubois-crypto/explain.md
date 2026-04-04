/**
 * storage-proof.ts — ENS storage proof fetcher + serializer
 *
 * Fetches eth_getProof for the VK hash text record on veryclear.eth,
 * and serializes it for the Nano's VERIFY_VK_STORAGE APDU (INS 0x64).
 *
 * Storage slot computation for PublicResolver text records:
 *   texts mapping is at base slot S in the PublicResolver contract.
 *   For texts[node][key]:
 *     outer = keccak256(abi.encode(node, S))
 *     inner = keccak256(abi.encode(keccak256(bytes(key)), outer))
 *   String value > 31 bytes → stored at keccak256(inner), length at inner.
 *   String value <= 31 bytes → stored inline at inner.
 */

import { ethers } from "ethers";

const MAINNET_RPC = "https://ethereum-rpc.publicnode.com";
const ENS_NAME = "veryclear.eth";
const RESOLVER_ADDR = "0xF29100983E058B709F3D539b0c765937B804AC15";
const VK_HASH_KEY = "vkHash:ERC20_approve";

/**
 * Compute storage slot for a text record in PublicResolver.
 * Tries base slots 0-15 and returns the one where the value matches.
 */
async function findTextRecordSlot(
  provider: ethers.JsonRpcProvider,
  resolverAddr: string,
  node: string,
  key: string,
  expectedValue: string
): Promise<{ slot: string; baseSlot: number } | null> {
  const keyHash = ethers.keccak256(ethers.toUtf8Bytes(key));

  for (let base = 0; base < 20; base++) {
    // outer = keccak256(abi.encode(node, base))
    const outer = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "uint256"],
        [node, base]
      )
    );
    // inner = keccak256(abi.encode(keccak256(key), outer))
    const inner = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32"],
        [keyHash, outer]
      )
    );

    // For short strings (<= 31 bytes), value is inline at `inner`
    // For long strings (> 31 bytes), `inner` stores length*2+1,
    //   data at keccak256(inner), keccak256(inner)+1, ...
    const raw = await provider.getStorage(resolverAddr, inner);
    if (raw === "0x" + "00".repeat(32)) continue;

    // Check if this looks like a string slot (last byte = length*2+1 for short strings)
    const lastByte = parseInt(raw.slice(-2), 16);
    if (lastByte % 2 === 1 && lastByte < 64) {
      // Short string: length = (lastByte - 1) / 2, data in upper bytes
      const len = (lastByte - 1) / 2;
      const strBytes = Buffer.from(raw.slice(2, 2 + len * 2), "hex");
      const decoded = strBytes.toString("utf8");
      if (decoded === expectedValue) {
        console.log(`[storage-proof] Found at base_slot=${base}, slot=${inner}`);
        return { slot: inner, baseSlot: base };
      }
    } else if (lastByte % 2 === 0) {
      // Long string: length = (value - 1) / 2, data at keccak256(slot)
      // Ignore for now — our 64-char hex string should be short (64 < 31? No, 64 > 31)
      // 64 chars = 64 bytes as UTF-8 → long string
      const totalLen = (BigInt(raw) - 1n) / 2n;
      if (totalLen > 0n && totalLen <= 256n) {
        const dataSlot = ethers.keccak256(inner);
        const nSlots = Math.ceil(Number(totalLen) / 32);
        let str = "";
        for (let s = 0; s < nSlots; s++) {
          const slotN = BigInt(dataSlot) + BigInt(s);
          const word = await provider.getStorage(
            resolverAddr,
            "0x" + slotN.toString(16).padStart(64, "0")
          );
          str += word.slice(2);
        }
        const decoded = Buffer.from(str.slice(0, Number(totalLen) * 2), "hex").toString("utf8");
        if (decoded === expectedValue) {
          console.log(`[storage-proof] Found long string at base_slot=${base}, slot=${inner}`);
          return { slot: inner, baseSlot: base };
        }
      }
    }
  }
  return null;
}

/**
 * Fetch the storage proof for the VK hash text record.
 */
export async function fetchVkStorageProof(vkHashHex: string): Promise<{
  storageHash: string;
  slot: string;
  proofNodes: string[];
  value: string;
} | null> {
  const provider = new ethers.JsonRpcProvider(MAINNET_RPC);
  const node = ethers.namehash(ENS_NAME);

  // Find the storage slot
  const found = await findTextRecordSlot(
    provider, RESOLVER_ADDR, node, VK_HASH_KEY, vkHashHex
  );
  if (!found) {
    console.error("[storage-proof] Could not find storage slot");
    return null;
  }

  // eth_getProof
  const proof = await provider.send("eth_getProof", [
    RESOLVER_ADDR,
    [found.slot],
    "latest",
  ]);

  return {
    storageHash: proof.storageHash,
    slot: found.slot,
    proofNodes: proof.storageProof[0].proof,
    value: proof.storageProof[0].value,
  };
}

/**
 * Serialize storage proof for the Nano APDU (INS 0x64).
 *
 * Format: storageHash(32) | slot(32) | nNodes(1) |
 *         nodeLen_0(2 BE) | node_0 | ... | expectedVkHash(32)
 */
export function serializeStorageProof(
  storageHash: string,
  slot: string,
  proofNodes: string[],
  expectedVkHash: string
): string {
  const parts: string[] = [];

  // storageHash (32 bytes)
  parts.push(storageHash.replace("0x", "").padStart(64, "0"));

  // slot (32 bytes)
  parts.push(slot.replace("0x", "").padStart(64, "0"));

  // nNodes (1 byte)
  parts.push(proofNodes.length.toString(16).padStart(2, "0"));

  // Each node: nodeLen(2 BE) | nodeData
  for (const nodeHex of proofNodes) {
    const data = nodeHex.replace("0x", "");
    const len = data.length / 2;
    parts.push(len.toString(16).padStart(4, "0"));
    parts.push(data);
  }

  // expectedVkHash (32 bytes)
  parts.push(expectedVkHash.replace("0x", "").padStart(64, "0"));

  return parts.join("");
}
