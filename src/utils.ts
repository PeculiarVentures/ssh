import { UnsupportedAlgorithmError } from './errors';
import { AlgorithmRegistry } from './registry';
import type { SshKeyType } from './types';

/**
 * Auto-detect SSH key type from WebCrypto CryptoKey
 */
export function getSshKeyTypeFromCryptoKey(cryptoKey: CryptoKey): SshKeyType {
  const sshType = AlgorithmRegistry.getSshTypeFromCryptoKey(cryptoKey);
  if (!sshType) {
    throw new UnsupportedAlgorithmError(cryptoKey.algorithm.name);
  }
  return sshType as SshKeyType;
}

// Reusable TextEncoder and TextDecoder instances
export const encoder = new TextEncoder();
export const decoder = new TextDecoder();
