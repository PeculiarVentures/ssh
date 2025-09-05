import { describe, expect, it, vi } from 'vitest';
import { AlgorithmRegistry } from './registry';

describe('AlgorithmRegistry', () => {
  it('should register and get algorithm binding', () => {
    const mockBinding = {
      importPublicSsh: vi.fn(),
      exportPublicSsh: vi.fn(),
      importPublicSpki: vi.fn(),
      exportPublicSpki: vi.fn(),
      importPrivatePkcs8: vi.fn(),
      exportPrivatePkcs8: vi.fn(),
      importPrivateSsh: vi.fn(),
      exportPrivateSsh: vi.fn(),
      sign: vi.fn(),
      verify: vi.fn(),
      encodeSignature: vi.fn(),
      decodeSignature: vi.fn(),
      supportsCryptoKey: vi.fn(),
      parsePublicKey: vi.fn(),
      writePublicKey: vi.fn(),
      getCertificateType: vi.fn(),
      getSignatureAlgo: vi.fn(),
    };
    AlgorithmRegistry.register('test', mockBinding);
    expect(AlgorithmRegistry.get('test')).toBe(mockBinding);
  });

  it('should throw error for unregistered algorithm', () => {
    expect(() => AlgorithmRegistry.get('unknown')).toThrow(/Unsupported key type: unknown/);
  });
});
