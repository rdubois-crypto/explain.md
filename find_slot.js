const { ethers } = require("ethers");
const p = new ethers.JsonRpcProvider("https://ethereum-rpc.publicnode.com");
const RESOLVER = "0xF29100983E058B709F3D539b0c765937B804AC15";
const ENS = "veryklear.eth";
const KEY = "vkHash:ERC20_approve";

(async () => {
  const node = ethers.namehash(ENS);
  const keyHash = ethers.keccak256(ethers.toUtf8Bytes(KEY));
  console.log("node:", node);
  console.log("keyHash:", keyHash);

  for (let base = 0; base < 30; base++) {
    // Strategy 1: simple mapping(bytes32 => mapping(string => string))
    // outer = keccak256(node || base)
    // inner = keccak256(keccak256(key) || outer)
    const outer1 = ethers.keccak256(ethers.solidityPacked(["bytes32", "uint256"], [node, base]));
    const inner1 = ethers.keccak256(ethers.solidityPacked(["bytes32", "bytes32"], [keyHash, outer1]));
    const v1 = await p.getStorage(RESOLVER, inner1);
    if (v1 !== "0x" + "00".repeat(32)) {
      console.log(`FOUND strategy=1 base=${base} slot=${inner1} val=${v1}`);
    }

    // Strategy 2: versioned mapping(uint64 => mapping(bytes32 => mapping(string => string)))
    // version = 0 (most common)
    for (let ver = 0; ver < 3; ver++) {
      const vSlot = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["uint64", "uint256"], [ver, base]));
      const nSlot = ethers.keccak256(ethers.solidityPacked(["bytes32", "bytes32"], [node, vSlot]));
      const kSlot = ethers.keccak256(ethers.solidityPacked(["bytes32", "bytes32"], [keyHash, nSlot]));
      const v2 = await p.getStorage(RESOLVER, kSlot);
      if (v2 !== "0x" + "00".repeat(32)) {
        console.log(`FOUND strategy=2 base=${base} ver=${ver} slot=${kSlot} val=${v2}`);
      }
    }
  }
  console.log("scan done");
})();
