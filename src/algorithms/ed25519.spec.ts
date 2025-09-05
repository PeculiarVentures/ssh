import { BufferSourceConverter } from 'pvtsutils';
import { describe, expect, it } from 'vitest';
import { getCrypto } from '../crypto';
import { AlgorithmRegistry } from '../registry';
import { SshReader, SshWriter } from '../wire';

describe('Ed25519 Algorithm', () => {
  const crypto = getCrypto();
  const ed25519Binding = AlgorithmRegistry.get('ssh-ed25519');

  it('should be registered', () => {
    expect(ed25519Binding).toBeDefined();
  });

  it('should import/export Ed25519 public key from SSH format', async () => {
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
    const sshBlob = await ed25519Binding.exportPublicSsh({
      publicKey: keyPair.publicKey,
      crypto,
    });

    // Import back
    const importedKey = await ed25519Binding.importPublicSsh({
      blob: sshBlob,
      crypto,
    });

    // Export both keys to raw format for comparison
    const originalRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const importedRaw = await crypto.subtle.exportKey('raw', importedKey);

    expect(new Uint8Array(originalRaw)).toEqual(new Uint8Array(importedRaw));
  });

  it('should import/export Ed25519 private key from PKCS#8 format', async () => {
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
      pkcs8: BufferSourceConverter.toUint8Array(pkcs8),
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
    const sshSignature = ed25519Binding.encodeSignature({
      signature: rawSignature,
      algo: 'ssh-ed25519',
    });

    // Decode back
    const decoded = ed25519Binding.decodeSignature({
      signature: sshSignature,
    });

    expect(decoded.algo).toBe('ssh-ed25519');
    expect(new Uint8Array(decoded.signature)).toEqual(new Uint8Array(rawSignature));
  });

  it('should import/export Ed25519 public key from SPKI format', async () => {
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
      spki: BufferSourceConverter.toUint8Array(spki),
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

  it('should parse Ed25519 public key from certificate format', () => {
    const ed25519Binding = AlgorithmRegistry.get('ssh-ed25519');
    expect(ed25519Binding.parsePublicKey).toBeDefined();

    // Create mock certificate data for Ed25519 (32 bytes public key)
    const mockPubKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      mockPubKey[i] = i;
    }

    const writer = new SshWriter();
    writer.writeUint32(mockPubKey.length); // length
    writer.writeBytes(mockPubKey); // public key data

    const reader = new SshReader(writer.toUint8Array());
    const publicKey = ed25519Binding.parsePublicKey(reader);

    expect(publicKey.type).toBe('ssh-ed25519');
    expect(publicKey.keyData).toBeDefined();

    // Verify the parsed key can be imported
    const importReader = new SshReader(publicKey.keyData);
    expect(importReader.readString()).toBe('ssh-ed25519');
    expect(importReader.readUint32()).toBe(32);
    const parsedPubKey = importReader.readBytes(32);
    expect(new Uint8Array(parsedPubKey)).toEqual(mockPubKey);
  });

  it('should return correct certificate type', () => {
    const ed25519Binding = AlgorithmRegistry.get('ssh-ed25519');
    expect(ed25519Binding.getCertificateType?.()).toBe('ssh-ed25519-cert-v01@openssh.com');
  });
});
