/**
 * Utility for loading test fixtures
 * Fixtures are stored as real SSH files for better realism and easier generation
 */

import { readFileSync } from 'fs';
import { join } from 'path';

const fixturesDir = join(__dirname, '..', 'fixtures');

// Helper function to read fixture file
function readFixture(filePath: string): string {
  return readFileSync(join(fixturesDir, filePath), 'utf8').trim();
}

// Helper function to read fixture file as Uint8Array
function readFixtureBinary(filePath: string): Uint8Array {
  const content = readFileSync(join(fixturesDir, filePath), 'utf8');
  // If it's PEM format, decode it
  if (content.includes('-----BEGIN')) {
    const base64 = content
      .replace(/-----BEGIN [^-]+-----/, '')
      .replace(/-----END [^-]+-----/, '')
      .replace(/\s/g, '');
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }
  return new Uint8Array(Buffer.from(content, 'binary'));
}

// SSH Keys
export const rsaKey = readFixture('rsa.pub');

export const ed25519Key = readFixture('ed25519.pub');

export const ecdsaP256Key = readFixture('ecdsa-p256.pub');

export const ecdsaP384Key = readFixture('ecdsa-p384.pub');

export const ecdsaP521Key = readFixture('ecdsa-p521.pub');

// SSH Private Keys (PKCS#8 format)
export const rsaPrivateKeyPkcs8 = readFixtureBinary('rsa.pkcs8');

export const ed25519PrivateKeyPkcs8 = readFixtureBinary('ed25519.pkcs8');

export const ecdsaP256PrivateKeyPkcs8 = readFixtureBinary('ecdsa-p256.pkcs8');

export const ecdsaP384PrivateKeyPkcs8 = readFixtureBinary('ecdsa-p384.pkcs8');

export const ecdsaP521PrivateKeyPkcs8 = readFixtureBinary('ecdsa-p521.pkcs8');

// SSH Private Keys (OpenSSH format)
export const rsaPrivateKeySsh = readFixture('rsa.ssh');

export const ed25519PrivateKeySsh = readFixture('ed25519.ssh');

export const ecdsaP256PrivateKeySsh = readFixture('ecdsa-p256.ssh');

export const ecdsaP384PrivateKeySsh = readFixture('ecdsa-p384.ssh');

export const ecdsaP521PrivateKeySsh = readFixture('ecdsa-p521.ssh');

// SSH Certificates
export const rsaCertificate = readFixture('rsa.cert');

export const ed25519Certificate = readFixture('ed25519.cert');

export const ecdsaP256Certificate = readFixture('ecdsa-p256.cert');

// Additional test certificates from certificate.spec.ts
export const testEd25519Cert = readFixture('ed25519.cert');

export const testEcdsaCert = readFixture('ecdsa-p256.cert');

/**
 * Helper function to get all SSH keys
 */
export function getAllKeys(): string[] {
  return [rsaKey, ed25519Key, ecdsaP256Key, ecdsaP384Key, ecdsaP521Key];
}

/**
 * Helper function to get all SSH private keys (PKCS#8)
 */
export function getAllPrivateKeysPkcs8(): Uint8Array[] {
  return [
    rsaPrivateKeyPkcs8,
    ed25519PrivateKeyPkcs8,
    ecdsaP256PrivateKeyPkcs8,
    ecdsaP384PrivateKeyPkcs8,
    ecdsaP521PrivateKeyPkcs8,
  ];
}

/**
 * Helper function to get all SSH private keys (OpenSSH format)
 */
export function getAllPrivateKeysSsh(): string[] {
  return [
    rsaPrivateKeySsh,
    ed25519PrivateKeySsh,
    ecdsaP256PrivateKeySsh,
    ecdsaP384PrivateKeySsh,
    ecdsaP521PrivateKeySsh,
  ];
}

export const testUserRsa = readFixture('rsa.cert');

export const testUserEd25519 = readFixture('ed25519.cert');

export const testUserEcdsa = readFixture('ecdsa-p256.cert');

/**
 * Helper function to get all SSH certificates
 */
export function getAllCertificates(): string[] {
  return [
    rsaCertificate,
    ed25519Certificate,
    ecdsaP256Certificate,
    testEd25519Cert,
    testEcdsaCert,
    testUserRsa,
    testUserEd25519,
    testUserEcdsa,
  ];
}
