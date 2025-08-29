import { describe, expect, it } from 'vitest';
import { getCrypto } from '../crypto';
import { SshPrivateKey } from './private_key';

describe('SshPrivateKey', () => {
  it('should create instance', async () => {
    // Create a real Ed25519 key for testing
    const crypto = getCrypto();
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign', 'verify'],
    );

    const key = await SshPrivateKey.fromWebCrypto(keyPair.privateKey);
    expect(key.keyType).toBe('ssh-ed25519');
  });

  // More tests will be added once AlgorithmRegistry has bindings
});
