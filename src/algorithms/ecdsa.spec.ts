import { describe, expect, it } from 'vitest';
import { ecdsaP384Key, ecdsaP521Key } from '../../tests/utils/testFixtures';
import { getCrypto } from '../crypto';
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

  it('should encode and decode SSH signature correctly for P-256', () => {
    const ecdsaBinding = AlgorithmRegistry.get('ecdsa-sha2-nistp256');
    expect(ecdsaBinding.encodeSshSignature).toBeDefined();
    expect(ecdsaBinding.decodeSshSignature).toBeDefined();

    // Create mock ECDSA signature (DER format, simplified for test)
    const mockSignature = new Uint8Array([0x30, 0x44, 0x02, 0x20, 0x01, 0x02, 0x03, 0x04]);

    // Encode to SSH format
    const sshSignature = ecdsaBinding.encodeSshSignature({
      signature: mockSignature,
      algo: 'ecdsa-sha2-nistp256',
    });

    // Decode back
    const decoded = ecdsaBinding.decodeSshSignature({
      signature: sshSignature,
    });

    expect(decoded.algo).toBe('ecdsa-sha2-nistp256');
    expect(new Uint8Array(decoded.signature)).toEqual(mockSignature);
  });

  it('should encode and decode SSH signature correctly for P-384', () => {
    const ecdsaBinding = AlgorithmRegistry.get('ecdsa-sha2-nistp384');
    expect(ecdsaBinding.encodeSshSignature).toBeDefined();
    expect(ecdsaBinding.decodeSshSignature).toBeDefined();

    // Create mock ECDSA signature (DER format, simplified for test)
    const mockSignature = new Uint8Array([0x30, 0x64, 0x02, 0x30, 0x01, 0x02, 0x03, 0x04]);

    // Encode to SSH format
    const sshSignature = ecdsaBinding.encodeSshSignature({
      signature: mockSignature,
      algo: 'ecdsa-sha2-nistp384',
    });

    // Decode back
    const decoded = ecdsaBinding.decodeSshSignature({
      signature: sshSignature,
    });

    expect(decoded.algo).toBe('ecdsa-sha2-nistp384');
    expect(new Uint8Array(decoded.signature)).toEqual(mockSignature);
  });

  it('should encode and decode SSH signature correctly for P-521', () => {
    const ecdsaBinding = AlgorithmRegistry.get('ecdsa-sha2-nistp521');
    expect(ecdsaBinding.encodeSshSignature).toBeDefined();
    expect(ecdsaBinding.decodeSshSignature).toBeDefined();

    // Create mock ECDSA signature (DER format, simplified for test)
    const mockSignature = new Uint8Array([0x30, 0x81, 0x88, 0x02, 0x42, 0x01, 0x02, 0x03]);

    // Encode to SSH format
    const sshSignature = ecdsaBinding.encodeSshSignature({
      signature: mockSignature,
      algo: 'ecdsa-sha2-nistp521',
    });

    // Decode back
    const decoded = ecdsaBinding.decodeSshSignature({
      signature: sshSignature,
    });

    expect(decoded.algo).toBe('ecdsa-sha2-nistp521');
    expect(new Uint8Array(decoded.signature)).toEqual(mockSignature);
  });

  it('should import P-384 public key from SSH format', async () => {
    const crypto = getCrypto();
    const ecdsaBinding = AlgorithmRegistry.get('ecdsa-sha2-nistp384');

    // Parse the SSH key string to get the key data
    const parsed = ecdsaP384Key.split(' ');
    const base64Data = parsed[1];
    const keyData = new Uint8Array(Buffer.from(base64Data, 'base64'));

    // Import the public key
    const cryptoKey = await ecdsaBinding.importPublicFromSsh({
      blob: keyData,
      crypto,
    });

    expect(cryptoKey).toBeDefined();
    expect(cryptoKey.type).toBe('public');
    expect((cryptoKey.algorithm as any).name).toBe('ECDSA');
    expect((cryptoKey.algorithm as any).namedCurve).toBe('P-384');
  });

  it('should import P-521 public key from SSH format', async () => {
    const crypto = getCrypto();
    const ecdsaBinding = AlgorithmRegistry.get('ecdsa-sha2-nistp521');

    // Parse the SSH key string to get the key data
    const parsed = ecdsaP521Key.split(' ');
    const base64Data = parsed[1];
    const keyData = new Uint8Array(Buffer.from(base64Data, 'base64'));

    // Import the public key
    const cryptoKey = await ecdsaBinding.importPublicFromSsh({
      blob: keyData,
      crypto,
    });

    expect(cryptoKey).toBeDefined();
    expect(cryptoKey.type).toBe('public');
    expect((cryptoKey.algorithm as any).name).toBe('ECDSA');
    expect((cryptoKey.algorithm as any).namedCurve).toBe('P-521');
  });

  it('should round-trip P-384 public key import/export', async () => {
    const crypto = getCrypto();
    const ecdsaBinding = AlgorithmRegistry.get('ecdsa-sha2-nistp384');

    // Parse the SSH key string to get the key data
    const parsed = ecdsaP384Key.split(' ');
    const base64Data = parsed[1];
    const originalKeyData = new Uint8Array(Buffer.from(base64Data, 'base64'));

    // Import the public key
    const cryptoKey = await ecdsaBinding.importPublicFromSsh({
      blob: originalKeyData,
      crypto,
    });

    // Export it back to SSH format
    const exportedKeyData = await ecdsaBinding.exportPublicToSsh({
      publicKey: cryptoKey,
      crypto,
    });

    // Compare the original and exported key data
    expect(new Uint8Array(exportedKeyData)).toEqual(originalKeyData);
  });

  it('should round-trip P-521 public key import/export', async () => {
    const crypto = getCrypto();
    const ecdsaBinding = AlgorithmRegistry.get('ecdsa-sha2-nistp521');

    // Parse the SSH key string to get the key data
    const parsed = ecdsaP521Key.split(' ');
    const base64Data = parsed[1];
    const originalKeyData = new Uint8Array(Buffer.from(base64Data, 'base64'));

    // Import the public key
    const cryptoKey = await ecdsaBinding.importPublicFromSsh({
      blob: originalKeyData,
      crypto,
    });

    // Export it back to SSH format
    const exportedKeyData = await ecdsaBinding.exportPublicToSsh({
      publicKey: cryptoKey,
      crypto,
    });

    // Compare the original and exported key data
    expect(new Uint8Array(exportedKeyData)).toEqual(originalKeyData);
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
