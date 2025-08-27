import { describe, expect, it } from 'vitest';
import { AlgorithmRegistry, getCrypto, setCrypto } from './index';

describe('Crypto Provider', () => {
  it('should return global crypto by default', () => {
    const crypto = getCrypto();
    expect(crypto).toBeDefined();
    expect(crypto.subtle).toBeDefined();
  });

  it('should allow setting custom crypto', () => {
    const mockCrypto = { subtle: {} as SubtleCrypto };
    setCrypto(mockCrypto);
    expect(getCrypto()).toBe(mockCrypto);
  });
});

describe('AlgorithmRegistry', () => {
  it('should register and get algorithm binding', () => {
    const mockBinding = {};
    AlgorithmRegistry.register('test', mockBinding);
    expect(AlgorithmRegistry.get('test')).toBe(mockBinding);
  });

  it('should return undefined for unregistered algorithm', () => {
    expect(AlgorithmRegistry.get('unknown')).toBeUndefined();
  });
});
