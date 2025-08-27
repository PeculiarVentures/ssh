import { describe, expect, it } from 'vitest';
import { SshPrivateKey } from './private_key';

describe('SshPrivateKey', () => {
  it('should create instance', async () => {
    // Mock CryptoKey
    const mockCryptoKey = {} as CryptoKey;
    const key = await SshPrivateKey.fromWebCrypto(mockCryptoKey, 'ssh-rsa');
    expect(key.keyType).toBe('ssh-rsa');
  });

  // More tests will be added once AlgorithmRegistry has bindings
});
