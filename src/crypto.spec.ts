import { describe, expect, it } from 'vitest';
import { getCrypto, setCrypto } from './crypto';

describe('Crypto Provider', () => {
  it('should return global crypto by default', () => {
    const crypto = getCrypto();
    expect(crypto).toBeDefined();
    expect(crypto.subtle).toBeDefined();
  });

  it('should allow setting custom crypto', () => {
    const mockCrypto = { subtle: {} as SubtleCrypto } as Crypto;
    setCrypto(mockCrypto);
    expect(getCrypto()).toBe(mockCrypto);
  });
});
