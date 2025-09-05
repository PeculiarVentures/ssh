import { readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { describe, expect, it } from 'vitest';
import { SSH } from '../src';
import { cleanupTempFiles, runSshKeygen } from './utils/compatibility';

const tmpDirPath = tmpdir();

// Define algorithms for key compatibility tests
const algorithms = [
  { name: 'RSA', sshType: 'rsa', bits: '2048', moduleType: 'rsa', expectedPrefix: 'ssh-rsa' },
  {
    name: 'ECDSA P-256',
    sshType: 'ecdsa',
    bits: '256',
    moduleType: 'ecdsa-p256',
    expectedPrefix: 'ecdsa-sha2-nistp256',
  },
  {
    name: 'ECDSA P-384',
    sshType: 'ecdsa',
    bits: '384',
    moduleType: 'ecdsa-p384',
    expectedPrefix: 'ecdsa-sha2-nistp384',
  },
  {
    name: 'ECDSA P-521',
    sshType: 'ecdsa',
    bits: '521',
    moduleType: 'ecdsa-p521',
    expectedPrefix: 'ecdsa-sha2-nistp521',
  },
  {
    name: 'Ed25519',
    sshType: 'ed25519',
    bits: '',
    moduleType: 'ed25519',
    expectedPrefix: 'ssh-ed25519',
  },
];

describe('Key Compatibility', () => {
  // Test: Module creates key, ssh-keygen can read it
  algorithms.forEach(algo => {
    it(`should export ${algo.name} public key to SSH format compatible with ssh-keygen`, async () => {
      const pubFile = join(
        tmpDirPath,
        `ssh-test-pub-mod-${algo.name.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}.pub`,
      );

      try {
        // Create key pair in module
        const keyPair = await SSH.createKeyPair(algo.moduleType);

        // Export public key to SSH format
        const publicSsh = `${await keyPair.publicKey.toSSH()} test@example.com`;
        writeFileSync(pubFile, `${publicSsh}\n`);

        // Verify the exported key has correct format
        expect(typeof publicSsh).toBe('string');
        expect(publicSsh.startsWith(algo.expectedPrefix)).toBe(true);

        // Try to read the key with ssh-keygen to verify compatibility
        try {
          runSshKeygen(['-l', '-f', pubFile]);
          // If no error, ssh-keygen can read the key
        } catch (error: any) {
          throw new Error(`ssh-keygen failed to read ${algo.name} key: ${error.message}`);
        }
      } finally {
        cleanupTempFiles(pubFile);
      }
    });
  });

  // Test: ssh-keygen creates key, Module can import it
  algorithms.forEach(algo => {
    it(`should import ${algo.name} public key from ssh-keygen`, async () => {
      const privFile = join(
        tmpDirPath,
        `ssh-test-priv-ssh-${algo.name.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}`,
      );

      try {
        // Generate key with ssh-keygen
        const genArgs = ['-t', algo.sshType, '-f', privFile, '-N', ''];
        if (algo.bits) genArgs.splice(2, 0, '-b', algo.bits);
        runSshKeygen(genArgs);

        // Read public key from file
        const pubContent = readFileSync(`${privFile}.pub`, 'utf8').trim();

        // Import into module
        const publicKey = await SSH.import(pubContent, { format: 'ssh' });
        expect((publicKey as any).keyType).toBe(algo.expectedPrefix);

        // Verify we can export it back to SSH format
        const exportedSsh = await (publicKey as any).toSSH();
        expect(typeof exportedSsh).toBe('string');
        expect(exportedSsh.length).toBeGreaterThan(0); // Just verify export works
      } finally {
        cleanupTempFiles(privFile, `${privFile}.pub`);
      }
    });
  });

  // Test: Module and ssh-keygen produce same thumbprint
  algorithms.forEach(algo => {
    it(`should produce same SHA256 thumbprint as ssh-keygen for ${algo.name}`, async () => {
      const pubFile = join(
        tmpDirPath,
        `ssh-test-thumbprint-${algo.name.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}.pub`,
      );

      try {
        // Create key pair in module
        const keyPair = await SSH.createKeyPair(algo.moduleType);

        // Export public key to SSH format
        const publicSsh = `${await keyPair.publicKey.toSSH()} test@example.com`;
        writeFileSync(pubFile, `${publicSsh}\n`);

        // Get thumbprint using module
        const moduleThumbprint = await SSH.thumbprint('sha256', keyPair.publicKey, 'ssh');

        // Get thumbprint using ssh-keygen
        const sshKeygenOutput = runSshKeygen(['-l', '-E', 'sha256', '-f', pubFile]);

        // Parse ssh-keygen output: "256 SHA256:base64hash comment (type)"
        const match = sshKeygenOutput.match(/SHA256:([A-Za-z0-9+/=]+)/);
        if (!match) {
          throw new Error(`Failed to parse ssh-keygen output: ${sshKeygenOutput}`);
        }
        const sshKeygenThumbprint = `SHA256:${match[1]}`;

        // Normalize base64 - remove padding for comparison
        const normalizeBase64 = (str: string) => str.replace(/=+$/, '');
        const normalizedModule = normalizeBase64(moduleThumbprint);
        const normalizedSsh = normalizeBase64(sshKeygenThumbprint);

        // Compare normalized thumbprints
        expect(normalizedModule).toBe(normalizedSsh);
      } finally {
        cleanupTempFiles(pubFile);
      }
    });
  });
});
