import { describe, expect, it } from 'vitest';
import { InvalidKeyDataError } from '../errors';
import { AlgorithmRegistry } from '../registry';
import { SshReader, SshWriter } from '../wire';

describe('RSA Algorithm', () => {
  const rsaBinding = AlgorithmRegistry.get('ssh-rsa');

  it('should be registered', () => {
    expect(rsaBinding).toBeDefined();
  });

  it('should parse RSA public key from certificate format', () => {
    const rsaBinding = AlgorithmRegistry.get('ssh-rsa');
    expect(rsaBinding.parsePublicKey).toBeDefined();

    // Create mock certificate data for RSA
    const writer = new SshWriter();
    writer.writeUint32(3); // e length
    writer.writeBytes(new Uint8Array([1, 0, 1])); // e = 65537
    writer.writeUint32(4); // n length
    writer.writeBytes(new Uint8Array([0, 1, 0, 1])); // n mock

    const reader = new SshReader(writer.toUint8Array());
    const parseMethod = rsaBinding.parsePublicKey;
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

  it('should encode and decode SSH signature correctly', () => {
    const rsaBinding = AlgorithmRegistry.get('ssh-rsa');
    expect(rsaBinding.encodeSignature).toBeDefined();
    expect(rsaBinding.decodeSignature).toBeDefined();

    // Create mock RSA signature (DER format, simplified for test)
    const mockSignature = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01]);

    // Encode to SSH format
    const sshSignature = rsaBinding.encodeSignature({
      signature: mockSignature,
      algo: 'rsa-sha2-256',
    });

    // Decode back
    const decoded = rsaBinding.decodeSignature({
      signature: sshSignature,
    });

    expect(decoded.algo).toBe('rsa-sha2-256');
    expect(new Uint8Array(decoded.signature)).toEqual(mockSignature);
  });

  it('should return correct certificate type', () => {
    const rsaBinding = AlgorithmRegistry.get('ssh-rsa');
    expect(rsaBinding.getCertificateType?.()).toBe('ssh-rsa-cert-v01@openssh.com');
  });

  it('should throw error for non-extractable private key in sign', async () => {
    const rsaBinding = AlgorithmRegistry.get('ssh-rsa');
    const crypto = globalThis.crypto;

    // Create a non-extractable private key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true, // extractable: true for public, but we need private
      ['sign', 'verify'],
    );

    // Make private key non-extractable by re-importing
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const nonExtractablePrivateKey = await crypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      false, // extractable: false
      ['sign'],
    );

    const testData = new Uint8Array([1, 2, 3]);

    await expect(
      rsaBinding.sign({ privateKey: nonExtractablePrivateKey, data: testData, crypto }),
    ).rejects.toThrow(InvalidKeyDataError);
  });

  it('should throw error for non-extractable public key in verify', async () => {
    const rsaBinding = AlgorithmRegistry.get('ssh-rsa');
    const crypto = globalThis.crypto;

    // Create a non-extractable public key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    );

    // Make public key non-extractable by re-importing
    const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const nonExtractablePublicKey = await crypto.subtle.importKey(
      'spki',
      spki,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      false, // extractable: false
      ['verify'],
    );

    const testData = new Uint8Array([1, 2, 3]);
    const signature = new Uint8Array(256); // dummy signature

    await expect(
      rsaBinding.verify({
        publicKey: nonExtractablePublicKey,
        signature,
        data: testData,
        crypto,
      }),
    ).rejects.toThrow(InvalidKeyDataError);
  });
});
