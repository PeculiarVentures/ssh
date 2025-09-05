let globalCrypto = globalThis.crypto;

export function setCrypto(crypto: Crypto): void {
  globalCrypto = crypto;
}

export function getCrypto(): Crypto {
  return globalCrypto;
}
