const { ethers } = require("ethers");
const p = new ethers.JsonRpcProvider("https://ethereum-rpc.publicnode.com");
const R = "0xF29100983E058B709F3D539b0c765937B804AC15";

(async () => {
  // Check EIP-1967 implementation slot
  const implSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
  const impl = await p.getStorage(R, implSlot);
  console.log("EIP-1967 impl:", impl);

  // Check EIP-1967 admin slot
  const adminSlot = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
  const admin = await p.getStorage(R, adminSlot);
  console.log("EIP-1967 admin:", admin);

  // Get bytecode size to see if it's a proxy
  const code = await p.getCode(R);
  console.log("Bytecode size:", code.length / 2 - 1, "bytes");

  // Try eth_getProof with a known-working text() call
  // Use debug_traceCall to find which slots are accessed
  const iface = new ethers.Interface([
    "function text(bytes32 node, string key) view returns (string)"
  ]);
  const node = ethers.namehash("veryklear.eth");
  const calldata = iface.encodeFunctionData("text", [node, "vkHash:ERC20_approve"]);
  
  try {
    const trace = await p.send("debug_traceCall", [
      { to: R, data: calldata },
      "latest",
      { tracer: "prestateTracer" }
    ]);
    console.log("\nTrace storage keys:", JSON.stringify(trace, null, 2).slice(0, 2000));
  } catch(e) {
    console.log("debug_traceCall not available:", e.message.slice(0, 100));
    
    // Fallback: try Etherscan-style approach
    // Use eth_getProof to ask the RPC directly for ALL storage
    console.log("\nTrying eth_getProof with empty slot list...");
    const proof = await p.send("eth_getProof", [R, [], "latest"]);
    console.log("storageHash:", proof.storageHash);
    console.log("stateRoot accessible: yes");
    console.log("nonce:", proof.nonce, "balance:", proof.balance);
  }
})();
