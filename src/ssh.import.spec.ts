import { describe, expect, it } from 'vitest';
import * as fixtures from '../tests/utils/testFixtures';
import { SshCertificate } from './cert/certificate';
import { SshPrivateKey } from './key/private_key';
import { SshPublicKey } from './key/public_key';
import { SSH } from './ssh';
import type { SshKeyType } from './types';

describe('SSH.import', () => {
  // Test data for all algorithms
  const algorithms = [
    {
      name: 'RSA',
      publicKey: fixtures.rsaKey,
      privateKeySsh: fixtures.rsaPrivateKeySsh,
      privateKeyPkcs8: fixtures.rsaPrivateKeyPkcs8,
      certificate: fixtures.rsaCertificate,
      type: 'ssh-rsa' as SshKeyType,
    },
    {
      name: 'Ed25519',
      publicKey: fixtures.ed25519Key,
      privateKeySsh: fixtures.ed25519PrivateKeySsh,
      privateKeyPkcs8: fixtures.ed25519PrivateKeyPkcs8,
      certificate: fixtures.ed25519Certificate,
      type: 'ssh-ed25519' as SshKeyType,
    },
    {
      name: 'ECDSA P-256',
      publicKey: fixtures.ecdsaP256Key,
      privateKeySsh: fixtures.ecdsaP256PrivateKeySsh,
      privateKeyPkcs8: fixtures.ecdsaP256PrivateKeyPkcs8,
      certificate: fixtures.ecdsaP256Certificate,
      type: 'ecdsa-sha2-nistp256' as SshKeyType,
    },
    {
      name: 'ECDSA P-384',
      publicKey: fixtures.ecdsaP384Key,
      privateKeySsh: fixtures.ecdsaP384PrivateKeySsh,
      privateKeyPkcs8: fixtures.ecdsaP384PrivateKeyPkcs8,
      certificate: null, // No certificate fixture for P-384
      type: 'ecdsa-sha2-nistp384' as SshKeyType,
    },
    {
      name: 'ECDSA P-521',
      publicKey: fixtures.ecdsaP521Key,
      privateKeySsh: fixtures.ecdsaP521PrivateKeySsh,
      privateKeyPkcs8: fixtures.ecdsaP521PrivateKeyPkcs8,
      certificate: null, // No certificate fixture for P-521
      type: 'ecdsa-sha2-nistp521' as SshKeyType,
    },
  ];

  describe('SSH Public Key Format', () => {
    algorithms.forEach(({ name, publicKey, type }) => {
      it(`should import ${name} public key without options`, async () => {
        const key = await SSH.import(publicKey);
        expect(key).toBeInstanceOf(SshPublicKey);
        expect((key as SshPublicKey).keyType).toBe(type);
      });

      it(`should import ${name} public key with explicit ssh format`, async () => {
        const key = await SSH.import(publicKey, { format: 'ssh' });
        expect(key).toBeInstanceOf(SshPublicKey);
        expect((key as SshPublicKey).keyType).toBe(type);
      });
    });
  });

  describe('SSH Private Key Format (OpenSSH)', () => {
    algorithms.forEach(({ name, privateKeySsh, type }) => {
      it(`should import ${name} private key without options`, async () => {
        const key = await SSH.import(privateKeySsh);
        expect(key).toBeInstanceOf(SshPrivateKey);
        expect((key as SshPrivateKey).keyType).toBe(type);
      });
    });

    it('should import RSA private key with explicit ssh format', async () => {
      const key = await SSH.import(fixtures.rsaPrivateKeySsh, { format: 'ssh' });
      expect(key).toBeInstanceOf(SshPrivateKey);
      expect((key as SshPrivateKey).keyType).toBe('ssh-rsa');
    });
  });

  describe('PKCS#8 Private Key Format', () => {
    algorithms.forEach(({ name, privateKeyPkcs8, type }) => {
      it(`should import ${name} private key with type`, async () => {
        const key = await SSH.import(privateKeyPkcs8, {
          format: 'pkcs8',
          type,
        });
        expect(key).toBeInstanceOf(SshPrivateKey);
        expect((key as SshPrivateKey).keyType).toBe(type);
      });

      it(`should auto-detect ${name} type from PKCS#8`, async () => {
        const key = await SSH.import(privateKeyPkcs8, { format: 'pkcs8' });
        expect(key).toBeInstanceOf(SshPrivateKey);
        expect((key as SshPrivateKey).keyType).toBe(type);
      });
    });

    it('should auto-detect PKCS#8 format and import without type', async () => {
      // When format is auto-detected as pkcs8, type should be auto-detected too
      const key = await SSH.import(fixtures.rsaPrivateKeyPkcs8);
      expect(key).toBeInstanceOf(SshPrivateKey);
      expect((key as SshPrivateKey).keyType).toBe('ssh-rsa');
    });
  });

  describe('SSH Certificate Format', () => {
    algorithms
      .filter(({ certificate }) => certificate !== null)
      .forEach(({ name, certificate, type }) => {
        it(`should import ${name} certificate without options`, async () => {
          const cert = await SSH.import(certificate as string);
          expect(cert).toBeInstanceOf(SshCertificate);
          expect((cert as SshCertificate).publicKey.keyType).toBe(type);
        });
      });

    it('should import RSA certificate with explicit ssh format', async () => {
      const cert = await SSH.import(fixtures.rsaCertificate, { format: 'ssh' });
      expect(cert).toBeInstanceOf(SshCertificate);
      expect((cert as SshCertificate).publicKey.keyType).toBe('ssh-rsa');
    });
  });

  describe('Format Detection', () => {
    it('should detect SSH public key format', async () => {
      const key = await SSH.import(fixtures.rsaKey);
      expect(key).toBeInstanceOf(SshPublicKey);
    });

    it('should detect SSH private key format', async () => {
      const key = await SSH.import(fixtures.ed25519PrivateKeySsh);
      expect(key).toBeInstanceOf(SshPrivateKey);
    });

    it('should detect SSH certificate format', async () => {
      const cert = await SSH.import(fixtures.rsaCertificate);
      expect(cert).toBeInstanceOf(SshCertificate);
    });

    it('should detect PKCS#8 format and auto-detect type', async () => {
      // PKCS#8 format and type are both auto-detected
      const key = await SSH.import(fixtures.rsaPrivateKeyPkcs8);
      expect(key).toBeInstanceOf(SshPrivateKey);
      expect((key as SshPrivateKey).keyType).toBe('ssh-rsa');
    });

    it('should handle invalid data gracefully', async () => {
      await expect(SSH.import('not a valid key')).rejects.toThrow();
    });

    it('should handle empty string gracefully', async () => {
      await expect(SSH.import('')).rejects.toThrow();
    });
  });

  describe('Round-trip Tests', () => {
    it('should export and re-import SSH public key', async () => {
      const key1 = (await SSH.import(fixtures.rsaKey)) as SshPublicKey;
      const exported = await key1.toSSH();
      const key2 = (await SSH.import(exported)) as SshPublicKey;

      expect(key2).toBeInstanceOf(SshPublicKey);
      expect(key2.keyType).toBe(key1.keyType);
    });

    it('should export and re-import SSH private key', async () => {
      const key1 = (await SSH.import(fixtures.ed25519PrivateKeySsh)) as SshPrivateKey;
      const exported = await key1.toSSH();
      const key2 = (await SSH.import(exported)) as SshPrivateKey;

      expect(key2).toBeInstanceOf(SshPrivateKey);
      expect(key2.keyType).toBe(key1.keyType);
    });

    it('should export to PKCS#8 and re-import with type', async () => {
      const key1 = (await SSH.import(fixtures.ed25519PrivateKeySsh)) as SshPrivateKey;
      const exported = await key1.toPKCS8();
      const key2 = (await SSH.import(exported, {
        format: 'pkcs8',
        type: 'ssh-ed25519',
      })) as SshPrivateKey;

      expect(key2).toBeInstanceOf(SshPrivateKey);
      expect(key2.keyType).toBe(key1.keyType);
    });

    it('should export to PKCS#8 and re-import without type (auto-detect)', async () => {
      const key1 = (await SSH.import(fixtures.rsaPrivateKeySsh)) as SshPrivateKey;
      const exported = await key1.toPKCS8();
      const key2 = (await SSH.import(exported, { format: 'pkcs8' })) as SshPrivateKey;

      expect(key2).toBeInstanceOf(SshPrivateKey);
      expect(key2.keyType).toBe(key1.keyType);
    });

    it('should export to PKCS#8 and re-import with full auto-detection', async () => {
      const key1 = (await SSH.import(fixtures.ecdsaP256PrivateKeySsh)) as SshPrivateKey;
      const exported = await key1.toPKCS8();
      // Auto-detect both format and type
      const key2 = (await SSH.import(exported)) as SshPrivateKey;

      expect(key2).toBeInstanceOf(SshPrivateKey);
      expect(key2.keyType).toBe(key1.keyType);
    });
  });

  describe('Cross-Algorithm Tests', () => {
    algorithms.forEach(({ name, publicKey, privateKeySsh, type }) => {
      it(`should import ${name} public key`, async () => {
        const key = await SSH.import(publicKey);
        expect(key).toBeInstanceOf(SshPublicKey);
        expect((key as SshPublicKey).keyType).toBe(type);
      });

      it(`should import ${name} private key`, async () => {
        const key = await SSH.import(privateKeySsh);
        expect(key).toBeInstanceOf(SshPrivateKey);
        expect((key as SshPrivateKey).keyType).toBe(type);
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle public key with comment', async () => {
      const keyWithComment = `${fixtures.rsaKey} user@hostname`;
      const key = await SSH.import(keyWithComment);
      expect(key).toBeInstanceOf(SshPublicKey);
      expect((key as SshPublicKey).keyType).toBe('ssh-rsa');
    });

    it('should handle public key with extra whitespace', async () => {
      const keyWithWhitespace = `  \n${fixtures.rsaKey}\n  `;
      const key = await SSH.import(keyWithWhitespace);
      expect(key).toBeInstanceOf(SshPublicKey);
      expect((key as SshPublicKey).keyType).toBe('ssh-rsa');
    });

    it('should handle private key with extra whitespace', async () => {
      const keyWithWhitespace = `\n\n${fixtures.ed25519PrivateKeySsh}\n\n`;
      const key = await SSH.import(keyWithWhitespace);
      expect(key).toBeInstanceOf(SshPrivateKey);
      expect((key as SshPrivateKey).keyType).toBe('ssh-ed25519');
    });
  });
});
