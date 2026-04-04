const { ethers } = require("ethers");
const crypto = require("crypto");

const RPC = "https://ethereum-rpc.publicnode.com";
const R = "0xF29100983E058B709F3D539b0c765937B804AC15";

(async () => {
  const e = ethers;
  const p = new e.JsonRpcProvider(RPC);
  const node = e.namehash("veryklear.eth");
  const keyBytes = e.toUtf8Bytes("vkHash:ERC20_approve");

  // Compute slots (base=10, ver=0)
  const s1 = e.keccak256(e.AbiCoder.defaultAbiCoder().encode(["uint256","uint256"],[0,10]));
  const s2 = e.keccak256(e.AbiCoder.defaultAbiCoder().encode(["bytes32","bytes32"],[node,s1]));
  const s3 = e.keccak256(e.concat([keyBytes, s2]));
  const dataSlot0 = e.keccak256(s3);
  const dataSlot1 = "0x" + (BigInt(dataSlot0)+1n).toString(16).padStart(64,"0");

  console.log("s3:", s3);
  console.log("dataSlot0:", dataSlot0);
  console.log("dataSlot1:", dataSlot1);

  // Read raw values
  const raw0 = await p.getStorage(R, dataSlot0);
  const raw1 = await p.getStorage(R, dataSlot1);
  console.log("\nraw val slot0:", raw0);
  console.log("raw val slot1:", raw1);
  console.log("decoded slot0:", Buffer.from(raw0.slice(2),"hex").toString("utf8"));
  console.log("decoded slot1:", Buffer.from(raw1.slice(2),"hex").toString("utf8"));

  // Fetch proof
  const proof = await p.send("eth_getProof", [R, [dataSlot0, dataSlot1], "latest"]);
  const sp0 = proof.storageProof[0];
  const sp1 = proof.storageProof[1];

  console.log("\n--- Proof 0 ---");
  console.log("key:", sp0.key);
  console.log("value:", sp0.value);
  console.log("proof nodes:", sp0.proof.length);

  console.log("\n--- Proof 1 ---");
  console.log("key:", sp1.key);
  console.log("value:", sp1.value);
  console.log("proof nodes:", sp1.proof.length);

  console.log("\nstorageHash:", proof.storageHash);

  // Verify locally: keccak256(proof[0]) should == storageHash
  const node0 = Buffer.from(sp0.proof[0].slice(2), "hex");
  const hash0 = e.keccak256(node0);
  console.log("\nkeccak256(proof0[0]):", hash0);
  console.log("matches storageHash:", hash0 === proof.storageHash);

  const node1 = Buffer.from(sp1.proof[0].slice(2), "hex");
  const hash1 = e.keccak256(node1);
  console.log("keccak256(proof1[0]):", hash1);
  console.log("matches storageHash:", hash1 === proof.storageHash);

  // Check what spf_verify expects:
  // MPT key = keccak256(slot)
  const mptKey0 = e.keccak256(dataSlot0);
  const mptKey1 = e.keccak256(dataSlot1);
  console.log("\nMPT key0 (keccak256(dataSlot0)):", mptKey0);
  console.log("MPT key1 (keccak256(dataSlot1)):", mptKey1);
  console.log("sp0.key from eth_getProof:", sp0.key);
  console.log("key0 matches:", mptKey0 === sp0.key);
})();
