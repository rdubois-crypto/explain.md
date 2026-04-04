const { ethers } = require("ethers");
const fs = require("fs");
const p = new ethers.JsonRpcProvider("https://ethereum-rpc.publicnode.com");
const R = "0xF29100983E058B709F3D539b0c765937B804AC15";
const node = ethers.namehash("veryklear.eth");
const keyBytes = ethers.toUtf8Bytes("vkHash:ERC20_approve");

(async () => {
  const s1 = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["uint256","uint256"],[0,10]));
  const s2 = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32","bytes32"],[node,s1]));
  const s3 = ethers.keccak256(ethers.concat([keyBytes, s2]));
  const dataSlot0 = ethers.keccak256(s3);
  
  const proof = await p.send("eth_getProof", [R, [dataSlot0], "latest"]);
  const sp = proof.storageProof[0];

  // Generate C test
  let c = '#include "storage_proof.h"\n#include <stdio.h>\n\n';
  c += `static const uint8_t storage_hash[32] = {${hexToC(proof.storageHash)}};\n`;
  c += `static const uint8_t slot[32] = {${hexToC(dataSlot0)}};\n`;
  
  sp.proof.forEach((n, i) => {
    const d = n.slice(2);
    c += `static const uint8_t node_${i}[] = {${hexToC(n)}};\n`;
  });
  
  c += `\nint main() {\n`;
  c += `  const uint8_t *nodes[] = {${sp.proof.map((_,i) => `node_${i}`).join(", ")}};\n`;
  c += `  uint32_t lens[] = {${sp.proof.map(n => (n.length-2)/2).join(", ")}};\n`;
  c += `  uint8_t value[32];\n`;
  c += `  SpfErr err = spf_verify(storage_hash, slot, nodes, lens, ${sp.proof.length}, value);\n`;
  c += `  printf("spf_verify result: %d\\n", err);\n`;
  c += `  if (err == SPF_OK) {\n`;
  c += `    printf("value: "); for(int i=0;i<32;i++) printf("%02x",value[i]); printf("\\n");\n`;
  c += `    printf("as text: "); for(int i=0;i<32;i++) printf("%c",value[i]); printf("\\n");\n`;
  c += `  }\n  return err;\n}\n`;
  
  fs.writeFileSync("test_proof_local.c", c);
  console.log("wrote test_proof_local.c");
  console.log("value from eth_getProof:", sp.value);
  console.log("compile: gcc -I<path_to_mpt_headers> -o test_proof test_proof_local.c && ./test_proof");
})();

function hexToC(h) {
  const d = h.replace("0x","");
  const bytes = [];
  for (let i=0; i<d.length; i+=2) bytes.push("0x"+d.substr(i,2));
  return bytes.join(",");
}
