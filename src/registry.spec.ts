import { describe, expect, it, vi } from 'vitest';
import { AlgorithmRegistry } from './registry';

describe('AlgorithmRegistry', () => {
  it('should register and get algorithm binding', () => {
    const mockBinding = {
      importPublicFromSsh: vi.fn(),
      exportPublicToSsh: vi.fn(),
      importPublicSpki: vi.fn(),
      exportPublicSpki: vi.fn(),
      importPrivatePkcs8: vi.fn(),
      exportPrivatePkcs8: vi.fn(),
      importPrivateFromSsh: vi.fn(),
      sign: vi.fn(),
      verify: vi.fn(),
      encodeSshSignature: vi.fn(),
      decodeSshSignature: vi.fn(),
      supportsCryptoKey: vi.fn(),
      parseCertificatePublicKey: vi.fn(),
      writeCertificatePublicKey: vi.fn(),
      getCertificateType: vi.fn(),
      getSignatureAlgo: vi.fn(),
    };
    AlgorithmRegistry.register('test', mockBinding);
    expect(AlgorithmRegistry.get('test')).toBe(mockBinding);
  });

  it('should throw error for unregistered algorithm', () => {
    expect(() => AlgorithmRegistry.get('unknown')).toThrow('Unsupported algorithm: unknown.');
  });
});
