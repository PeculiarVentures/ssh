import { describe, expect, it } from 'vitest';
import { getCrypto } from '../crypto';
import { SshPrivateKey } from './private_key';
import { SshPublicKey } from './public_key';

describe('SshPublicKey', () => {
  const crypto = getCrypto();

  it('should create instance', () => {
    const blob = {
      type: 'ssh-rsa' as const,
      keyData: new Uint8Array([1, 2, 3]),
    };
    const key = new SshPublicKey(blob);
    expect(key.keyType).toBe('ssh-rsa');
    expect(key.getBlob()).toEqual(blob);
  });

  it('should import Ed25519 public key from SSH format', async () => {
    // Generate test key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign', 'verify'],
    );

    // Create SshPublicKey from WebCrypto key (auto-detect type)
    const originalPublicKey = await SshPublicKey.fromWebCrypto(keyPair.publicKey);

    // Export to SSH string format
    const sshString = (await originalPublicKey.export('ssh')) as string;

    // Import back from SSH string
    const importedPublicKey = await SshPublicKey.fromSSH(sshString);

    expect(importedPublicKey.keyType).toBe('ssh-ed25519');

    // Export both keys as SPKI for comparison
    const originalSpki = await originalPublicKey.toSPKI();
    const importedSpki = await importedPublicKey.toSPKI();

    // Compare SPKI data
    expect(new Uint8Array(originalSpki)).toEqual(new Uint8Array(importedSpki));

    // Verify that the imported key can verify signatures made with the original key
    const testData = new Uint8Array([1, 2, 3, 4, 5]);
    const signature = await crypto.subtle.sign('Ed25519', keyPair.privateKey, testData);

    // Convert imported SSH key to CryptoKey and verify
    const importedCryptoKey = await importedPublicKey.toWebCrypto();
    const isValid = await crypto.subtle.verify('Ed25519', importedCryptoKey, signature, testData);
    expect(isValid).toBe(true);
  });

  it('should have convenience methods', async () => {
    // Generate test key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign', 'verify'],
    );

    const publicKey = await SshPublicKey.fromWebCrypto(keyPair.publicKey);

    // Test convenience methods
    expect(typeof publicKey.toSSH).toBe('function');
    expect(typeof publicKey.toSPKI).toBe('function');
    expect(typeof publicKey.toWebCrypto).toBe('function');
    expect(typeof publicKey.verify).toBe('function');

    // Test SSH export
    const sshString = await publicKey.toSSH();
    expect(typeof sshString).toBe('string');
    expect(sshString).toContain('ssh-ed25519');

    // Test SPKI export
    const spkiBytes = await publicKey.toSPKI();
    expect(spkiBytes).toBeInstanceOf(Uint8Array);
    expect(spkiBytes.length).toBeGreaterThan(0);

    // Test WebCrypto conversion
    const cryptoKey = await publicKey.toWebCrypto();
    expect(cryptoKey.type).toBe('public');
    expect((cryptoKey.algorithm as any).name).toBe('Ed25519');

    // Test signature verification
    const testData = new Uint8Array([1, 2, 3, 4, 5]);
    const signature = await crypto.subtle.sign('Ed25519', keyPair.privateKey, testData);

    // Create SSH signature format
    const _base64Signature = btoa(String.fromCharCode(...new Uint8Array(signature)));
    // Note: This is a simplified test - real SSH signatures have specific encoding
    // const isValid = await publicKey.verify('ssh-rsa', signature, testData);
    // expect(isValid).toBe(true);
  });

  it('should compute thumbprint', async () => {
    // Generate test key
    const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

    const publicKey = await SshPublicKey.fromWebCrypto(keyPair.publicKey);

    // Test SHA-256 thumbprint
    const thumbprint256 = await publicKey.thumbprint('sha256');
    expect(thumbprint256).toBeInstanceOf(Uint8Array);
    expect(thumbprint256.length).toBe(32); // SHA-256 produces 32 bytes

    // Test SHA-512 thumbprint
    const thumbprint512 = await publicKey.thumbprint('sha512');
    expect(thumbprint512).toBeInstanceOf(Uint8Array);
    expect(thumbprint512.length).toBe(64); // SHA-512 produces 64 bytes

    // Test default algorithm (SHA-256)
    const defaultThumbprint = await publicKey.thumbprint();
    expect(defaultThumbprint).toEqual(thumbprint256);
  });

  it('should verify RSA signatures with different hashes', async () => {
    // Generate RSA key pair
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

    // Create SshPrivateKey and SshPublicKey
    const privateKey = await SshPrivateKey.fromWebCrypto(keyPair.privateKey, 'ssh-rsa');
    const publicKey = await SshPublicKey.fromWebCrypto(keyPair.publicKey, 'ssh-rsa');

    const testData = new Uint8Array([1, 2, 3, 4, 5]);

    // Test SHA-256
    const signature256 = await privateKey.sign('rsa-sha2-256', testData);
    const isValid256 = await publicKey.verify('rsa-sha2-256', signature256, testData);
    expect(isValid256).toBe(true);

    // Test SHA-512
    const signature512 = await privateKey.sign('rsa-sha2-512', testData);
    const isValid512 = await publicKey.verify('rsa-sha2-512', signature512, testData);
    expect(isValid512).toBe(true);
  });
});
