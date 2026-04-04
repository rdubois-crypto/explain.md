const { ethers } = require("ethers");
const p = new ethers.JsonRpcProvider("https://ethereum-rpc.publicnode.com");
const R = "0xF29100983E058B709F3D539b0c765937B804AC15";
const node = ethers.namehash("veryklear.eth");
const key = "vkHash:ERC20_approve";
const keyBytes = ethers.toUtf8Bytes(key);

(async () => {
  console.log("node:", node);
  console.log("key:", key, "(" + keyBytes.length + " bytes)");

  // For mapping(string => V) at slot p:
  //   slot = keccak256(bytes(key) || p)   ← raw bytes, NOT keccak256(key)!

  for (let base = 0; base < 20; base++) {
    // recordVersions[node] is probably 0
    for (let ver = 0; ver < 3; ver++) {
      // versionable_texts[ver][node][key]
      // Level 1: mapping(uint64 => ...) at base
      const s1 = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(["uint256","uint256"], [ver, base])
      );
      // Level 2: mapping(bytes32 => ...) at s1
      const s2 = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(["bytes32","bytes32"], [node, s1])
      );
      // Level 3: mapping(string => string) at s2
      // Solidity: keccak256(bytes(key) || uint256(s2))
      const s3 = ethers.keccak256(
        ethers.concat([keyBytes, s2])
      );

      const v = await p.getStorage(R, s3);
      if (v !== "0x" + "00".repeat(32)) {
        console.log(`\nFOUND! base=${base} ver=${ver}`);
        console.log(`  s1 (ver mapping):  ${s1}`);
        console.log(`  s2 (node mapping): ${s2}`);
        console.log(`  s3 (key mapping):  ${s3}`);
        console.log(`  raw value: ${v}`);

        // Decode string: if last byte is odd and < 64 → short string
        const lastByte = parseInt(v.slice(-2), 16);
        if (lastByte % 2 === 1 && lastByte <= 62) {
          const len = (lastByte - 1) / 2;
          const str = Buffer.from(v.slice(2, 2 + len * 2), "hex").toString("utf8");
          console.log(`  decoded (short): "${str}"`);
        } else {
          // Long string: length = (value-1)/2, data at keccak256(s3)
          const totalLen = Number((BigInt(v) - 1n) / 2n);
          console.log(`  long string, length=${totalLen}`);
          const dataSlot = ethers.keccak256(s3);
          let hex = "";
          const nSlots = Math.ceil(totalLen / 32);
          for (let i = 0; i < nSlots; i++) {
            const ds = "0x" + (BigInt(dataSlot) + BigInt(i)).toString(16).padStart(64, "0");
            const word = await p.getStorage(R, ds);
            hex += word.slice(2);
          }
          const str = Buffer.from(hex.slice(0, totalLen * 2), "hex").toString("utf8");
          console.log(`  decoded (long): "${str}"`);
          console.log(`  data slot: ${dataSlot}`);
        }
        process.exit(0);
      }
    }
    process.stdout.write(".");
  }
  console.log("\nnot found");
})();
