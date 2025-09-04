import { describe, expect, it } from 'vitest';
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

describe('SSH Unified API', () => {
  describe('import', () => {
    it('should import SSH public key automatically', async () => {
      const key = await SSH.import(rsaKey);
      expect(key).toBeInstanceOf(SshPublicKey);
      expect((key as SshPublicKey).type).toBe('ssh-rsa');
    });

    it('should import SSH private key automatically', async () => {
      const key = await SSH.import(rsaPrivateKeySsh);
      expect(key).toBeInstanceOf(SshPrivateKey);
      expect((key as SshPrivateKey).keyType).toBe('ssh-rsa');
    });

    it('should import with explicit format', async () => {
      const key = await SSH.import(ed25519Key, { format: 'ssh' });
      expect(key).toBeInstanceOf(SshPublicKey);
      expect((key as SshPublicKey).type).toBe('ssh-ed25519');
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
      expect(publicKey.type).toBe('ssh-ed25519');

      // Test signing/verification
      const testData = new Uint8Array([1, 2, 3, 4, 5]);
      const signature = await privateKey.sign(privateKey.keyType, testData);
      const isValid = await publicKey.verify(privateKey.keyType, signature, testData);
      expect(isValid).toBe(true);
    });

    it('should create Ed25519 key pair with object algorithm', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair({ name: 'ed25519' });

      expect(privateKey.keyType).toBe('ssh-ed25519');
      expect(publicKey.type).toBe('ssh-ed25519');
    });

    it('should create RSA key pair', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair('rsa');

      expect(privateKey.keyType).toBe('ssh-rsa');
      expect(publicKey.type).toBe('ssh-rsa');
    });

    it('should create RSA key pair with custom size', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair({
        name: 'rsa',
        modulusLength: 3072,
      });

      expect(privateKey.keyType).toBe('ssh-rsa');
      expect(publicKey.type).toBe('ssh-rsa');
    });

    it('should create ECDSA P-256 key pair', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair('ecdsa-p256');

      expect(privateKey.keyType).toBe('ecdsa-sha2-nistp256');
      expect(publicKey.type).toBe('ecdsa-sha2-nistp256');
    });

    it('should create ECDSA P-256 key pair with object algorithm', async () => {
      const { privateKey, publicKey } = await SSH.createKeyPair({ name: 'ecdsa-p256' });

      expect(privateKey.keyType).toBe('ecdsa-sha2-nistp256');
      expect(publicKey.type).toBe('ecdsa-sha2-nistp256');
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
    expect(publicKey.type).toBe('ssh-ed25519');
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
