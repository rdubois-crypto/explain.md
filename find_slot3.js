const { ethers } = require("ethers");
const p = new ethers.JsonRpcProvider("https://ethereum-rpc.publicnode.com");
const R = "0xF29100983E058B709F3D539b0c765937B804AC15";
const node = ethers.namehash("veryklear.eth");
const key = "vkHash:ERC20_approve";

// The resolver is an ERC-634 text resolver
// Let's read it via the contract ABI to confirm it works
const resolver = new ethers.Contract(R, [
  "function text(bytes32 node, string key) view returns (string)"
], p);

(async () => {
  // Confirm the value is readable via ABI
  const val = await resolver.text(node, key);
  console.log("text() returns:", val);
  console.log("length:", val.length, "bytes as UTF8");
  
  // Now brute-force scan ALL non-zero storage slots around the contract
  // Strategy: read slots 0-30 directly to understand the contract layout
  console.log("\n--- Raw storage slots 0-30 ---");
  for (let i = 0; i < 30; i++) {
    const s = "0x" + i.toString(16).padStart(64, "0");
    const v = await p.getStorage(R, s);
    if (v !== "0x" + "00".repeat(32)) {
      console.log(`  slot ${i}: ${v}`);
    }
  }
  
  // Now try to trace the actual call using eth_getStorageAt
  // The text() function in PublicResolver reads from:
  // versionable_texts[recordVersions[node]][node][key]
  // 
  // Let's find recordVersions mapping. It's typically slot 0.
  // recordVersions is mapping(bytes32 => uint64)
  console.log("\n--- recordVersions[node] scan ---");
  for (let rvBase = 0; rvBase < 30; rvBase++) {
    const rvSlot = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "uint256"], [node, rvBase])
    );
    const rv = await p.getStorage(R, rvSlot);
    if (rv !== "0x" + "00".repeat(32)) {
      console.log(`  recordVersions base=${rvBase} → version=${BigInt(rv)}`);
    }
  }

  console.log("\ndone");
})();
