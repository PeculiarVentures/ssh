import { describe, expect, it } from 'vitest';
import { AlgorithmRegistry } from '../registry';
import { SshReader, SshWriter } from '../wire';

describe('ECDSA Algorithm', () => {
  it('should parse ECDSA P-256 public key from certificate format', () => {
    const ecdsaBinding = AlgorithmRegistry.get('ecdsa-sha2-nistp256');
    expect(ecdsaBinding.parseCertificatePublicKey).toBeDefined();

    // Create mock certificate data for ECDSA P-256
    const mockPubKey = new Uint8Array(65);
    mockPubKey[0] = 0x04; // uncompressed point
    for (let i = 1; i < 65; i++) {
      mockPubKey[i] = i % 256;
    }

    const writer = new SshWriter();
    writer.writeString('nistp256'); // curve name
    writer.writeUint32(mockPubKey.length); // length
    writer.writeBytes(mockPubKey); // public key point

    const reader = new SshReader(writer.toUint8Array());
    if (!ecdsaBinding.parseCertificatePublicKey) {
      throw new Error('parseCertificatePublicKey method not found');
    }
    const publicKey = ecdsaBinding.parseCertificatePublicKey(reader);

    expect(publicKey.type).toBe('ecdsa-sha2-nistp256');
    expect(publicKey.keyData).toBeDefined();

    // Verify the parsed key can be imported
    const importReader = new SshReader(publicKey.keyData);
    expect(importReader.readString()).toBe('ecdsa-sha2-nistp256');
    expect(importReader.readString()).toBe('nistp256');
    const parsedPubKey = importReader.readMpInt();
    expect(new Uint8Array(parsedPubKey)).toEqual(mockPubKey);
  });

  it('should parse ECDSA P-384 public key from certificate format', () => {
    const ecdsaBinding = AlgorithmRegistry.get('ecdsa-sha2-nistp384');
    expect(ecdsaBinding.parseCertificatePublicKey).toBeDefined();

    // Create mock certificate data for ECDSA P-384
    const mockPubKey = new Uint8Array(97);
    mockPubKey[0] = 0x04; // uncompressed point
    for (let i = 1; i < 97; i++) {
      mockPubKey[i] = i % 256;
    }

    const writer = new SshWriter();
    writer.writeString('nistp384'); // curve name
    writer.writeUint32(mockPubKey.length); // length
    writer.writeBytes(mockPubKey); // public key point

    const reader = new SshReader(writer.toUint8Array());
    if (!ecdsaBinding.parseCertificatePublicKey) {
      throw new Error('parseCertificatePublicKey method not found');
    }
    const publicKey = ecdsaBinding.parseCertificatePublicKey(reader);

    expect(publicKey.type).toBe('ecdsa-sha2-nistp384');
    expect(publicKey.keyData).toBeDefined();

    // Verify the parsed key can be imported
    const importReader = new SshReader(publicKey.keyData);
    expect(importReader.readString()).toBe('ecdsa-sha2-nistp384');
    expect(importReader.readString()).toBe('nistp384');
    const parsedPubKey = importReader.readMpInt();
    expect(new Uint8Array(parsedPubKey)).toEqual(mockPubKey);
  });

  it('should parse ECDSA P-521 public key from certificate format', () => {
    const ecdsaBinding = AlgorithmRegistry.get('ecdsa-sha2-nistp521');
    expect(ecdsaBinding.parseCertificatePublicKey).toBeDefined();

    // Create mock certificate data for ECDSA P-521
    const mockPubKey = new Uint8Array(133);
    mockPubKey[0] = 0x04; // uncompressed point
    for (let i = 1; i < 133; i++) {
      mockPubKey[i] = i % 256;
    }

    const writer = new SshWriter();
    writer.writeString('nistp521'); // curve name
    writer.writeUint32(mockPubKey.length); // length
    writer.writeBytes(mockPubKey); // public key point

    const reader = new SshReader(writer.toUint8Array());
    if (!ecdsaBinding.parseCertificatePublicKey) {
      throw new Error('parseCertificatePublicKey method not found');
    }
    const publicKey = ecdsaBinding.parseCertificatePublicKey(reader);

    expect(publicKey.type).toBe('ecdsa-sha2-nistp521');
    expect(publicKey.keyData).toBeDefined();

    // Verify the parsed key can be imported
    const importReader = new SshReader(publicKey.keyData);
    expect(importReader.readString()).toBe('ecdsa-sha2-nistp521');
    expect(importReader.readString()).toBe('nistp521');
    const parsedPubKey = importReader.readMpInt();
    expect(new Uint8Array(parsedPubKey)).toEqual(mockPubKey);
  });

  it('should return correct certificate types', () => {
    expect(AlgorithmRegistry.get('ecdsa-sha2-nistp256').getCertificateType?.()).toBe(
      'ecdsa-sha2-nistp256-cert-v01@openssh.com',
    );
    expect(AlgorithmRegistry.get('ecdsa-sha2-nistp384').getCertificateType?.()).toBe(
      'ecdsa-sha2-nistp384-cert-v01@openssh.com',
    );
    expect(AlgorithmRegistry.get('ecdsa-sha2-nistp521').getCertificateType?.()).toBe(
      'ecdsa-sha2-nistp521-cert-v01@openssh.com',
    );
  });
});
