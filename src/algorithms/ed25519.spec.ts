import { describe, expect, it } from 'vitest';
import { getCrypto } from '../crypto';
import { AlgorithmRegistry } from '../registry';

describe('Ed25519 Algorithm', () => {
  const crypto = getCrypto();
  const ed25519Binding = AlgorithmRegistry.get('ssh-ed25519');

  it('should be registered', () => {
    expect(ed25519Binding).toBeDefined();
  });

  it('should import/export Ed25519 public key from SSH format', async () => {
    if (!ed25519Binding) {
      throw new Error('Ed25519 binding not found');
    }

    // Generate test key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign', 'verify'],
    );

    // Export to SSH format
    const sshBlob = await ed25519Binding.exportPublicToSsh({
      publicKey: keyPair.publicKey,
      crypto,
    });

    // Import back
    const importedKey = await ed25519Binding.importPublicFromSsh({
      blob: sshBlob,
      crypto,
    });

    // Export both keys to raw format for comparison
    const originalRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const importedRaw = await crypto.subtle.exportKey('raw', importedKey);

    expect(new Uint8Array(originalRaw)).toEqual(new Uint8Array(importedRaw));
  });

  it('should import/export Ed25519 private key from PKCS#8 format', async () => {
    if (!ed25519Binding) {
      throw new Error('Ed25519 binding not found');
    }

    // Generate test key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign', 'verify'],
    );

    // Export private key to PKCS#8 via WebCrypto
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

    // Import via our binding
    const importedKey = await ed25519Binding.importPrivatePkcs8({
      pkcs8,
      crypto,
    });

    // Export back via our binding
    const exportedPkcs8 = await ed25519Binding.exportPrivatePkcs8({
      privateKey: importedKey,
      crypto,
    });

    // Compare PKCS#8
    expect(new Uint8Array(pkcs8)).toEqual(new Uint8Array(exportedPkcs8));
  });

  it('should sign and verify data', async () => {
    if (!ed25519Binding) {
      throw new Error('Ed25519 binding not found');
    }

    // Generate test key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign', 'verify'],
    );

    const testData = new Uint8Array([1, 2, 3, 4, 5]);

    // Sign data
    const signature = await ed25519Binding.sign({
      privateKey: keyPair.privateKey,
      data: testData,
      crypto,
    });

    // Verify signature
    const isValid = await ed25519Binding.verify({
      publicKey: keyPair.publicKey,
      signature,
      data: testData,
      crypto,
    });

    expect(isValid).toBe(true);
  });

  it('should encode/decode SSH signature', async () => {
    if (!ed25519Binding) {
      throw new Error('Ed25519 binding not found');
    }

    // Generate test key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign', 'verify'],
    );

    const testData = new Uint8Array([1, 2, 3, 4, 5]);

    // Sign data
    const rawSignature = await ed25519Binding.sign({
      privateKey: keyPair.privateKey,
      data: testData,
      crypto,
    });

    // Encode to SSH format
    const sshSignature = ed25519Binding.encodeSshSignature({
      signature: rawSignature,
      algo: 'ssh-ed25519',
    });

    // Decode back
    const decoded = ed25519Binding.decodeSshSignature({
      signature: sshSignature,
    });

    expect(decoded.algo).toBe('ssh-ed25519');
    expect(new Uint8Array(decoded.signature)).toEqual(new Uint8Array(rawSignature));
  });

  it('should import/export Ed25519 public key from SPKI format', async () => {
    if (!ed25519Binding) {
      throw new Error('Ed25519 binding not found');
    }

    // Generate test key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign', 'verify'],
    );

    // Export public key to SPKI via WebCrypto
    const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);

    // Import via our binding
    const importedKey = await ed25519Binding.importPublicSpki({
      spki,
      crypto,
    });

    // Export back via our binding
    const exportedSpki = await ed25519Binding.exportPublicSpki({
      publicKey: importedKey,
      crypto,
    });

    // Compare SPKI
    expect(new Uint8Array(spki)).toEqual(new Uint8Array(exportedSpki));
  });
});
