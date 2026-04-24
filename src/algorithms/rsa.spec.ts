import { describe, expect, it } from 'vitest';
import { AlgorithmRegistry } from '../registry';
import { SshReader, SshWriter } from '../wire';

describe('RSA Algorithm', () => {
  const rsaBinding = AlgorithmRegistry.get('ssh-rsa');
  const rsaSha512Binding = AlgorithmRegistry.get('rsa-sha2-512');

  async function generateRsaKeyPair(hash: 'SHA-256' | 'SHA-512' = 'SHA-256') {
    return globalThis.crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash,
      },
      true,
      ['sign', 'verify'],
    );
  }

  async function toNonExtractablePrivateKey(privateKey: CryptoKey, crypto: Crypto) {
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
    return crypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      false,
      ['sign'],
    );
  }

  async function toNonExtractablePublicKey(publicKey: CryptoKey, crypto: Crypto) {
    const spki = await crypto.subtle.exportKey('spki', publicKey);
    return crypto.subtle.importKey(
      'spki',
      spki,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      false,
      ['verify'],
    );
  }

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
    const publicKey = rsaBinding.parsePublicKey(reader);

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

  it('should sign with a non-extractable private key when the key hash already matches', async () => {
    const crypto = globalThis.crypto;
    const keyPair = await generateRsaKeyPair('SHA-256');
    const nonExtractablePrivateKey = await toNonExtractablePrivateKey(keyPair.privateKey, crypto);

    const testData = new Uint8Array([1, 2, 3]);
    const signature = await rsaBinding.sign({
      privateKey: nonExtractablePrivateKey,
      data: testData,
      crypto,
    });

    await expect(
      rsaBinding.verify({
        publicKey: keyPair.publicKey,
        signature,
        data: testData,
        crypto,
      }),
    ).resolves.toBe(true);
  });

  it('should verify with a non-extractable public key when the key hash already matches', async () => {
    const crypto = globalThis.crypto;
    const keyPair = await generateRsaKeyPair('SHA-256');
    const nonExtractablePublicKey = await toNonExtractablePublicKey(keyPair.publicKey, crypto);

    const testData = new Uint8Array([1, 2, 3]);
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', keyPair.privateKey, testData);

    await expect(
      rsaBinding.verify({
        publicKey: nonExtractablePublicKey,
        signature: new Uint8Array(signature),
        data: testData,
        crypto,
      }),
    ).resolves.toBe(true);
  });

  it('should re-import an extractable private key when switching RSA hash algorithms', async () => {
    const crypto = globalThis.crypto;
    const keyPair = await generateRsaKeyPair('SHA-256');
    const testData = new Uint8Array([1, 2, 3, 4]);

    const signature = await rsaSha512Binding.sign({
      privateKey: keyPair.privateKey,
      data: testData,
      crypto,
    });

    await expect(
      rsaSha512Binding.verify({
        publicKey: keyPair.publicKey,
        signature,
        data: testData,
        crypto,
      }),
    ).resolves.toBe(true);
  });

  it('should throw an informative error for non-extractable private keys when RSA hash re-import is required', async () => {
    const crypto = globalThis.crypto;
    const keyPair = await generateRsaKeyPair('SHA-256');
    const nonExtractablePrivateKey = await toNonExtractablePrivateKey(keyPair.privateKey, crypto);
    const testData = new Uint8Array([1, 2, 3]);

    await expect(
      rsaSha512Binding.sign({ privateKey: nonExtractablePrivateKey, data: testData, crypto }),
    ).rejects.toThrow(
      'Invalid key data: RSA private key uses SHA-256 but rsa-sha2-512 requires SHA-512. The key is not extractable, so it cannot be re-imported with SHA-512.',
    );
  });

  it('should throw an informative error for non-extractable public keys when RSA hash re-import is required', async () => {
    const crypto = globalThis.crypto;
    const keyPair = await generateRsaKeyPair('SHA-256');
    const nonExtractablePublicKey = await toNonExtractablePublicKey(keyPair.publicKey, crypto);
    const testData = new Uint8Array([1, 2, 3]);
    const signature = await rsaSha512Binding.sign({
      privateKey: keyPair.privateKey,
      data: testData,
      crypto,
    });

    await expect(
      rsaSha512Binding.verify({
        publicKey: nonExtractablePublicKey,
        signature,
        data: testData,
        crypto,
      }),
    ).rejects.toThrow(
      'Invalid key data: RSA public key uses SHA-256 but rsa-sha2-512 requires SHA-512. The key is not extractable, so it cannot be re-imported with SHA-512.',
    );
  });
});
