const { ethers } = require("ethers");
const p = new ethers.JsonRpcProvider("https://ethereum-rpc.publicnode.com");
const R = "0xF29100983E058B709F3D539b0c765937B804AC15";
const node = ethers.namehash("veryklear.eth");
const key = "vkHash:ERC20_approve";
const keyHash = ethers.keccak256(ethers.toUtf8Bytes(key));

// Try to read recordVersions[node] for each possible base slot of recordVersions
async function trySlot(base, ver, label) {
  // versionable_texts[ver][node][key]
  // Level 1: keccak256(uint256(ver) || uint256(base))
  const s1 = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["uint256","uint256"],[ver,base]));
  // Level 2: keccak256(node || s1)
  const s2 = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32","bytes32"],[node,s1]));
  // Level 3: keccak256(keccak256(key) || s2)
  const s3 = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32","bytes32"],[keyHash,s2]));
  const v = await p.getStorage(R, s3);
  if (v !== "0x"+"00".repeat(32)) {
    console.log(`FOUND ${label} base=${base} ver=${ver} slot=${s3} raw=${v}`);
    return true;
  }
  return false;
}

(async () => {
  console.log("node:", node);
  console.log("keyHash:", keyHash);

  // 1. First find recordVersions[node]
  console.log("\n--- Scanning recordVersions ---");
  for (let rvBase = 0; rvBase < 20; rvBase++) {
    const rvSlot = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["bytes32","uint256"],[node,rvBase])
    );
    const rv = await p.getStorage(R, rvSlot);
    if (rv !== "0x"+"00".repeat(32)) {
      console.log(`recordVersions at base=${rvBase}: version=${BigInt(rv)}`);
    }
  }

  // 2. Brute force versionable_texts[ver][node][key]
  console.log("\n--- Scanning versionable_texts ---");
  for (let base = 0; base < 20; base++) {
    for (let ver = 0; ver < 5; ver++) {
      await trySlot(base, ver, "abi.encode");
    }
  }

  // 3. Try with solidityPacked instead of abi.encode
  console.log("\n--- Alt: solidityPacked ---");
  for (let base = 0; base < 20; base++) {
    for (let ver = 0; ver < 5; ver++) {
      const s1 = ethers.keccak256(ethers.solidityPacked(["uint256","uint256"],[ver,base]));
      const s2 = ethers.keccak256(ethers.solidityPacked(["bytes32","bytes32"],[node,s1]));
      const s3 = ethers.keccak256(ethers.solidityPacked(["bytes32","bytes32"],[keyHash,s2]));
      const v = await p.getStorage(R, s3);
      if (v !== "0x"+"00".repeat(32)) {
        console.log(`FOUND packed base=${base} ver=${ver} slot=${s3} raw=${v}`);
      }
    }
  }

  // 4. Try the EXISTING known-working key too
  console.log("\n--- Try existing key 0xa0b8... on veryclear.eth ---");
  const node2 = ethers.namehash("veryclear.eth");
  const key2 = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
  const kh2 = ethers.keccak256(ethers.toUtf8Bytes(key2));
  for (let base = 0; base < 20; base++) {
    for (let ver = 0; ver < 5; ver++) {
      const s1 = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["uint256","uint256"],[ver,base]));
      const s2 = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32","bytes32"],[node2,s1]));
      const s3 = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32","bytes32"],[kh2,s2]));
      const v = await p.getStorage(R, s3);
      if (v !== "0x"+"00".repeat(32)) {
        console.log(`FOUND veryclear base=${base} ver=${ver} slot=${s3} raw=${v}`);
      }
    }
  }

  console.log("\ndone");
})();
