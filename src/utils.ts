import { AlgorithmRegistry } from './registry';
import type { SshKeyType } from './types';

/**
 * Auto-detect SSH key type from WebCrypto CryptoKey
 */
export function getSshKeyTypeFromCryptoKey(cryptoKey: CryptoKey): SshKeyType {
  return AlgorithmRegistry.getSshTypeFromCryptoKey(cryptoKey) as SshKeyType;
}

// Reusable TextEncoder and TextDecoder instances
export const encoder = new TextEncoder();
export const decoder = new TextDecoder();
