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

// SSH Keys
export const rsaKey = readFixture('rsa.pub');

export const ed25519Key = readFixture('ed25519.pub');

export const ecdsaP256Key = readFixture('ecdsa-p256.pub');

export const ecdsaP384Key = readFixture('ecdsa-p384.pub');

export const ecdsaP521Key = readFixture('ecdsa-p521.pub');

// SSH Certificates
export const rsaCertificate = readFixture('rsa.cert');

export const ed25519Certificate = readFixture('ed25519.cert');

export const ecdsaP256Certificate = readFixture('ecdsa-p256.cert');

// Additional test certificates from certificate.spec.ts
export const testCertNew = readFixture('test-cert-new.cert');

export const testEd25519Cert = readFixture('ed25519.cert');

export const testEcdsaCert = readFixture('ecdsa-p256.cert');

/**
 * Helper function to get all SSH keys
 */
export function getAllKeys(): string[] {
  return [rsaKey, ed25519Key, ecdsaP256Key, ecdsaP384Key, ecdsaP521Key];
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
    testCertNew,
    testEd25519Cert,
    testEcdsaCert,
    testUserRsa,
    testUserEd25519,
    testUserEcdsa,
  ];
}
