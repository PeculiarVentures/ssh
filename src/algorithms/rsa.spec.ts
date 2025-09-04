import { describe, expect, it } from 'vitest';
import { AlgorithmRegistry } from '../registry';
import { SshReader, SshWriter } from '../wire';

describe('RSA Algorithm', () => {
  const rsaBinding = AlgorithmRegistry.get('ssh-rsa');

  it('should be registered', () => {
    expect(rsaBinding).toBeDefined();
  });

  it('should parse RSA public key from certificate format', () => {
    const rsaBinding = AlgorithmRegistry.get('ssh-rsa');
    expect(rsaBinding.parseCertificatePublicKey).toBeDefined();

    // Create mock certificate data for RSA
    const writer = new SshWriter();
    writer.writeUint32(3); // e length
    writer.writeBytes(new Uint8Array([1, 0, 1])); // e = 65537
    writer.writeUint32(4); // n length
    writer.writeBytes(new Uint8Array([0, 1, 0, 1])); // n mock

    const reader = new SshReader(writer.toUint8Array());
    const parseMethod = rsaBinding.parseCertificatePublicKey;
    expect(parseMethod).toBeDefined();
    if (!parseMethod) {
      throw new Error('parseCertificatePublicKey method not found');
    }
    const publicKey = parseMethod(reader);

    expect(publicKey.type).toBe('ssh-rsa');
    expect(publicKey.keyData).toBeDefined();

    // Verify the parsed key can be imported
    const importReader = new SshReader(publicKey.keyData);
    expect(importReader.readString()).toBe('ssh-rsa');
    // Should be able to read mpint for e and n
    expect(() => importReader.readMpInt()).not.toThrow();
    expect(() => importReader.readMpInt()).not.toThrow();
  });

  it('should return correct certificate type', () => {
    const rsaBinding = AlgorithmRegistry.get('ssh-rsa');
    expect(rsaBinding.getCertificateType?.()).toBe('ssh-rsa-cert-v01@openssh.com');
  });
});
