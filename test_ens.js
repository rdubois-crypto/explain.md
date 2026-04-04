const {ethers} = require('ethers');
const p = new ethers.JsonRpcProvider('https://ethereum-rpc.publicnode.com');
(async()=>{
  const r = await p.getResolver('veryklear.eth');
  if (!r) { console.log('no resolver'); return; }
  console.log('resolver:', r.address);
  for (const k of [
    'vkHash:ERC20_approve',
    'vkHash',
    'cd361ed5f2a52e4e4bb981b8c6b47a72679c3e367e5132e219929ad54cd877bb',
    '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
  ]) {
    const v = await r.getText(k);
    if (v) console.log('  key=' + k, ' -> ', v);
    else console.log('  key=' + k, ' -> (empty)');
  }
})();
