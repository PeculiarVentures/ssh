import { describe, expect, it } from 'vitest';
import { SshPublicKey } from './public_key';

describe('SshPublicKey', () => {
  it('should create instance', () => {
    const blob = {
      type: 'ssh-rsa' as const,
      keyData: new Uint8Array([1, 2, 3]),
    };
    const key = new SshPublicKey(blob);
    expect(key.type).toBe('ssh-rsa');
    expect(key.getBlob()).toEqual(blob);
  });

  // More tests will be added once AlgorithmRegistry has bindings
});
