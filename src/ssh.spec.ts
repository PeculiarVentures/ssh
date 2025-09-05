import { assert, describe, expect, it } from 'vitest';
import {
  ecdsaP256Key,
  ed25519Key,
  ed25519PrivateKeySsh,
  rsaKey,
  rsaPrivateKeySsh,
} from '../tests/utils/testFixtures';
import { SshPrivateKey } from './key/private_key';
import { SshPublicKey } from './key/public_key';
import { SSH } from './ssh';
import { SshObject } from './types';

describe('SSH Unified API', () => {
  describe('import', () => {
    it('should import SSH public key automatically', async () => {
      const key = await SSH.import(rsaKey);
      expect(key).toBeInstanceOf(SshPublicKey);
      expect((key as SshPublicKey).keyType).toBe('ssh-rsa');
    });

    it('should import SSH private key automatically', async () => {
      const key = await SSH.import(rsaPrivateKeySsh);
      expect(key).toBeInstanceOf(SshPrivateKey);
      expect((key as SshPrivateKey).keyType).toBe('ssh-rsa');
    });

    it('should import with explicit format', async () => {
      const key = await SSH.import(ed25519Key, { format: 'ssh' });
      expect(key).toBeInstanceOf(SshPublicKey);
      expect((key as SshPublicKey).keyType).toBe('ssh-ed25519');
    });

    it('should throw on unsupported format', async () => {
      await expect(SSH.import('invalid data')).rejects.toThrow();
    });
  });

  describe('createKeyPair', () => {
    it('should create Ed25519 key pair', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair('ed25519');

      expect(privateKey).toBeInstanceOf(SshPrivateKey);
      expect(publicKey).toBeInstanceOf(SshPublicKey);
      expect(privateKey.keyType).toBe('ssh-ed25519');
      expect(publicKey.keyType).toBe('ssh-ed25519');

      // Test signing/verification
      const testData = new Uint8Array([1, 2, 3, 4, 5]);
      const signature = await privateKey.sign(privateKey.keyType, testData);
      const isValid = await publicKey.verify(privateKey.keyType, signature, testData);
      expect(isValid).toBe(true);
    });

    it('should create Ed25519 key pair with object algorithm', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair({ name: 'ed25519' });

      expect(privateKey.keyType).toBe('ssh-ed25519');
      expect(publicKey.keyType).toBe('ssh-ed25519');
    });

    it('should create RSA key pair', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair('rsa');

      expect(privateKey.keyType).toBe('ssh-rsa');
      expect(publicKey.keyType).toBe('ssh-rsa');
    });

    it('should create RSA key pair with custom size', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair({
        name: 'rsa',
        modulusLength: 3072,
      });

      expect(privateKey.keyType).toBe('ssh-rsa');
      expect(publicKey.keyType).toBe('ssh-rsa');
    });

    it('should create ECDSA P-256 key pair', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair('ecdsa-p256');

      expect(privateKey.keyType).toBe('ecdsa-sha2-nistp256');
      expect(publicKey.keyType).toBe('ecdsa-sha2-nistp256');
    });

    it('should create ECDSA P-256 key pair with object algorithm', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair({ name: 'ecdsa-p256' });

      expect(privateKey.keyType).toBe('ecdsa-sha2-nistp256');
      expect(publicKey.keyType).toBe('ecdsa-sha2-nistp256');
    });

    it('should throw on unsupported algorithm', async () => {
      await expect(SSH.createKeyPair('invalid' as any)).rejects.toThrow();
    });

    it('should throw on unsupported algorithm object', async () => {
      await expect(SSH.createKeyPair({ name: 'invalid' } as any)).rejects.toThrow();
    });
  });

  describe('createCertificate', () => {
    it('should create certificate builder', async () => {
      const publicKey = (await SSH.import(ed25519Key)) as SshPublicKey;
      const builder = SSH.createCertificate(publicKey);

      expect(builder).toBeDefined();
      expect(typeof builder.setKeyId).toBe('function');
      expect(typeof builder.addPrincipal).toBe('function');
    });
  });

  describe('thumbprint', () => {
    it('should compute thumbprint for public key in hex format', async () => {
      const publicKey = await SSH.import(rsaKey);
      const thumbprint = await SSH.thumbprint('sha256', publicKey, 'hex');

      expect(typeof thumbprint).toBe('string');
      expect(thumbprint).toMatch(/^[0-9a-f]+$/);
      expect(thumbprint.length).toBe(64); // 32 bytes * 2 hex chars
    });

    it('should compute thumbprint for public key in base64 format', async () => {
      const publicKey = await SSH.import(rsaKey);
      const thumbprint = await SSH.thumbprint('sha256', publicKey, 'base64');

      expect(typeof thumbprint).toBe('string');
      expect(thumbprint).toMatch(/^[A-Za-z0-9+/=]+$/);
    });

    it('should compute thumbprint for public key in SSH format', async () => {
      const publicKey = await SSH.import(rsaKey);
      const thumbprint = await SSH.thumbprint('sha256', publicKey, 'ssh');

      expect(typeof thumbprint).toBe('string');
      expect(thumbprint).toMatch(/^SHA256:[A-Za-z0-9+/=]+$/);
    });

    it('should compute thumbprint for private key', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair('ed25519');
      const thumbprint = await SSH.thumbprint('sha256', privateKey, 'ssh');

      expect(typeof thumbprint).toBe('string');
      expect(thumbprint).toMatch(
        /^SHA256:[A-Za-z0-9+/=]+$/,

        // Verify thumbprint matches public key thumbprint
      );
      const publicKeyThumbprint = await SSH.thumbprint('sha256', publicKey, 'ssh');
      expect(thumbprint).toBe(publicKeyThumbprint);
    });

    it('should compute thumbprint for certificate', async () => {
      // Create a certificate for testing
      const publicKey = await SSH.import(ed25519Key);
      const { privateKey: signerPrivateKey, publicKey: signerPublicKey } =
        await SSH.createKeyPair('ed25519');
      assert.ok(publicKey instanceof SshPublicKey);
      const builder = SSH.createCertificate(publicKey);
      const cert = await builder
        .setKeyId('test-cert')
        .addPrincipal('user')
        .setValidity(Math.floor(Date.now() / 1000), Math.floor(Date.now() / 1000) + 86400) // 1 day
        .sign({
          signatureKey: signerPublicKey,
          privateKey: await signerPrivateKey.toWebCrypto(),
        });

      const thumbprint = await SSH.thumbprint('sha256', cert, 'ssh');
      expect(typeof thumbprint).toBe('string');
      expect(thumbprint).toMatch(/^SHA256:[A-Za-z0-9+/=]+$/);

      // Verify thumbprint matches public key thumbprint
      const publicKeyThumbprint = await SSH.thumbprint('sha256', publicKey, 'ssh');
      expect(thumbprint).toBe(publicKeyThumbprint);
    });

    it('should compute thumbprint for signature with public key', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair('ed25519');
      const testData = new Uint8Array([1, 2, 3, 4, 5]);
      const signature = await SSH.sign('ssh-ed25519', privateKey, testData, {
        format: 'ssh-signature',
      });

      const thumbprint = await SSH.thumbprint('sha256', signature, 'ssh');
      expect(typeof thumbprint).toBe('string');
      expect(thumbprint).toMatch(/^SHA256:[A-Za-z0-9+/=]+$/);

      // Verify thumbprint matches public key thumbprint
      const publicKeyThumbprint = await SSH.thumbprint('sha256', publicKey, 'ssh');
      expect(thumbprint).toBe(publicKeyThumbprint);
    });

    it('should throw error for signature without public key', async () => {
      const { privateKey } = await SSH.createKeyPair('ed25519');
      const testData = new Uint8Array([1, 2, 3, 4, 5]);
      const signature = await SSH.sign('ssh-ed25519', privateKey, testData, {
        format: 'legacy', // Legacy format doesn't include public key
      });

      await expect(SSH.thumbprint('sha256', signature, 'ssh')).rejects.toThrow(
        'Signature does not contain a public key',
      );
    });

    it('should throw error for unsupported object type', async () => {
      class CustomObject extends SshObject {
        type = 'custom';
        toSSH(): Promise<string> {
          throw new Error('Method not implemented.');
        }
      }
      await expect(SSH.thumbprint('sha256', new CustomObject(), 'ssh')).rejects.toThrow(
        'Unsupported object type for thumbprint',
      );
    });

    it('should support SHA-512 algorithm', async () => {
      const publicKey = (await SSH.import(rsaKey)) as SshPublicKey;
      const thumbprint = await SSH.thumbprint('sha512', publicKey, 'ssh');

      expect(typeof thumbprint).toBe('string');
      expect(thumbprint).toMatch(/^SHA512:[A-Za-z0-9+/=]+$/);
    });
  });
});

describe('Enhanced SshPrivateKey API', () => {
  it('should have convenience export methods', async () => {
    const key = (await SSH.import(ed25519PrivateKeySsh)) as SshPrivateKey;

    // Test convenience methods
    expect(typeof key.toWebCrypto).toBe('function');
    expect(typeof key.toPKCS8).toBe('function');
    expect(typeof key.getPublicKey).toBe('function');

    // Test WebCrypto method
    const cryptoKey = key.toWebCrypto();
    expect(cryptoKey).toBeDefined();
    expect(cryptoKey.type).toBe('private');

    // Test getting public key
    const publicKey = await key.getPublicKey();
    expect(publicKey).toBeInstanceOf(SshPublicKey);
    expect(publicKey.keyType).toBe('ssh-ed25519');
  });
});

describe('Enhanced SshPublicKey API', () => {
  it('should have convenience export methods', async () => {
    const key = (await SSH.import(ecdsaP256Key)) as SshPublicKey;

    // Test convenience methods
    expect(typeof key.toSSH).toBe('function');
    expect(typeof key.toSPKI).toBe('function');
    expect(typeof key.toWebCrypto).toBe('function');
    expect(typeof key.verify).toBe('function');

    // Test SSH export
    const sshString = await key.toSSH();
    expect(typeof sshString).toBe('string');
    expect(sshString).toContain('ecdsa-sha2-nistp256');

    // Test SPKI export
    const spkiBytes = await key.toSPKI();
    expect(spkiBytes).toBeInstanceOf(Uint8Array);
    expect(spkiBytes.length).toBeGreaterThan(0);

    // Test WebCrypto
    const cryptoKey = await key.toWebCrypto();
    expect(cryptoKey).toBeDefined();
    expect(cryptoKey.type).toBe('public');
  });
});
