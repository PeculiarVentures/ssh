import { describe, expect, it } from 'vitest';
import {
  ecdsaP256PrivateKeyPkcs8,
  ecdsaP256PrivateKeySsh,
  ecdsaP384PrivateKeyPkcs8,
  ecdsaP384PrivateKeySsh,
  ecdsaP521PrivateKeyPkcs8,
  ecdsaP521PrivateKeySsh,
  ed25519PrivateKeyPkcs8,
  ed25519PrivateKeySsh,
  rsaPrivateKeyPkcs8,
  rsaPrivateKeySsh,
} from '../../tests/utils/testFixtures';
import { getCrypto } from '../crypto';
import { SshPrivateKey } from './private_key';

describe('SshPrivateKey', () => {
  it('should create instance', async () => {
    // Create a real Ed25519 key for testing
    const crypto = getCrypto();
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign', 'verify'],
    );

    const key = await SshPrivateKey.fromWebCrypto(keyPair.privateKey);
    expect(key.keyType).toBe('ssh-ed25519');
  });

  it('should import RSA private key from PKCS#8', async () => {
    const key = await SshPrivateKey.importPrivatePkcs8(rsaPrivateKeyPkcs8, 'ssh-rsa');
    expect(key.keyType).toBe('ssh-rsa');
  });

  it('should import Ed25519 private key from PKCS#8', async () => {
    const key = await SshPrivateKey.importPrivatePkcs8(ed25519PrivateKeyPkcs8, 'ssh-ed25519');
    expect(key.keyType).toBe('ssh-ed25519');
  });

  it('should import ECDSA P-256 private key from PKCS#8', async () => {
    const key = await SshPrivateKey.importPrivatePkcs8(
      ecdsaP256PrivateKeyPkcs8,
      'ecdsa-sha2-nistp256',
    );
    expect(key.keyType).toBe('ecdsa-sha2-nistp256');
  });

  it('should import ECDSA P-384 private key from PKCS#8', async () => {
    const key = await SshPrivateKey.importPrivatePkcs8(
      ecdsaP384PrivateKeyPkcs8,
      'ecdsa-sha2-nistp384',
    );
    expect(key.keyType).toBe('ecdsa-sha2-nistp384');
  });

  it('should import ECDSA P-521 private key from PKCS#8', async () => {
    const key = await SshPrivateKey.importPrivatePkcs8(
      ecdsaP521PrivateKeyPkcs8,
      'ecdsa-sha2-nistp521',
    );
    expect(key.keyType).toBe('ecdsa-sha2-nistp521');
  });

  it('should import RSA private key from SSH format', async () => {
    const key = await SshPrivateKey.importPrivateFromSsh(rsaPrivateKeySsh);
    expect(key.keyType).toBe('ssh-rsa');
  });

  it('should import Ed25519 private key from SSH format', async () => {
    const key = await SshPrivateKey.importPrivateFromSsh(ed25519PrivateKeySsh);
    expect(key.keyType).toBe('ssh-ed25519');
  });

  it('should import ECDSA P-256 private key from SSH format', async () => {
    const key = await SshPrivateKey.importPrivateFromSsh(ecdsaP256PrivateKeySsh);
    expect(key.keyType).toBe('ecdsa-sha2-nistp256');
  });

  it('should import ECDSA P-384 private key from SSH format', async () => {
    const key = await SshPrivateKey.importPrivateFromSsh(ecdsaP384PrivateKeySsh);
    expect(key.keyType).toBe('ecdsa-sha2-nistp384');
  });

  it('should import ECDSA P-521 private key from SSH format', async () => {
    const key = await SshPrivateKey.importPrivateFromSsh(ecdsaP521PrivateKeySsh);
    expect(key.keyType).toBe('ecdsa-sha2-nistp521');
  });
});
