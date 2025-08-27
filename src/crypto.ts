export interface CryptoLike {
  subtle: SubtleCrypto;
}

let globalCrypto: CryptoLike = globalThis.crypto;

export function setCrypto(crypto: CryptoLike): void {
  globalCrypto = crypto;
}

export function getCrypto(): CryptoLike {
  return globalCrypto;
}
