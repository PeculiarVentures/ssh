import { readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { describe, expect, it } from 'vitest';
import { SSH, SshPublicKey, SshSignature } from '../src';
import { cleanupTempFiles, runSshKeygen } from './utils/compatibility';

const tmpDirPath = tmpdir();

// Define algorithms for signature compatibility tests
const algorithms = [
  { name: 'RSA SHA-256', sshType: 'rsa', bits: '2048', moduleType: 'rsa', sigAlgo: 'rsa-sha2-256' },
  {
    name: 'RSA SHA-512',
    sshType: 'rsa',
    bits: '2048',
    moduleType: 'rsa',
    sigAlgo: 'rsa-sha2-512',
  },
  {
    name: 'ECDSA P-256',
    sshType: 'ecdsa',
    bits: '256',
    moduleType: 'ecdsa-p256',
    sigAlgo: 'ecdsa-sha2-nistp256',
  },
  {
    name: 'ECDSA P-384',
    sshType: 'ecdsa',
    bits: '384',
    moduleType: 'ecdsa-p384',
    sigAlgo: 'ecdsa-sha2-nistp384',
  },
  {
    name: 'ECDSA P-521',
    sshType: 'ecdsa',
    bits: '521',
    moduleType: 'ecdsa-p521',
    sigAlgo: 'ecdsa-sha2-nistp521',
  },
  { name: 'Ed25519', sshType: 'ed25519', bits: '', moduleType: 'ed25519', sigAlgo: 'ssh-ed25519' },
];

describe('Signature Compatibility', () => {
  // Test: ssh-keygen signs, Module verifies
  algorithms.forEach(algo => {
    it(`should verify signature created by ssh-keygen (${algo.name})`, async () => {
      const privFile = join(
        tmpDirPath,
        `ssh-test-sig-term-${algo.name.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}`,
      );
      const dataFile = join(
        tmpDirPath,
        `ssh-test-data-${algo.name.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}`,
      );
      const sigFile = `${dataFile}.sig`;

      try {
        // Generate key with ssh-keygen
        const genArgs = ['-t', algo.sshType, '-f', privFile, '-N', ''];
        if (algo.bits) genArgs.splice(2, 0, '-b', algo.bits);
        runSshKeygen(genArgs);

        // Read public key content
        const pubContent = readFileSync(`${privFile}.pub`, 'utf8').trim();

        // Create data file
        const data = new Uint8Array([10, 20, 30, 40, 50]);
        writeFileSync(dataFile, data);

        // Sign data with ssh-keygen
        const signArgs = ['-Y', 'sign', '-f', privFile, '-n', 'file', dataFile];
        if (algo.sshType === 'rsa') {
          // For RSA, specify the exact signature algorithm
          signArgs.splice(2, 0, '-t', algo.sigAlgo);
        } else {
          // For other algorithms, use the signature algorithm
          signArgs.splice(2, 0, '-t', algo.sigAlgo);
        }
        runSshKeygen(signArgs);

        // Read signature from .sig file
        const signatureOutput = readFileSync(sigFile, 'utf8');

        // Parse the SSH SIGNATURE using SshSignature.fromText
        const sshSignature = SshSignature.fromText(signatureOutput);

        // ssh-keygen generates SSH SIGNATURE format (RFC 4253), not legacy format
        expect(sshSignature.format).toBe('ssh-signature');

        // For RSA, ssh-keygen may use SHA-512 even when we specify SHA-256
        if (algo.sshType === 'rsa' && algo.sigAlgo === 'rsa-sha2-256') {
          // ssh-keygen often defaults to SHA-512 for RSA
          expect(['rsa-sha2-256', 'rsa-sha2-512']).toContain(sshSignature.algorithm);
        } else {
          expect(sshSignature.algorithm).toBe(algo.sigAlgo);
        }

        // Import public key into module
        const publicKey = await SSH.import(pubContent, { format: 'ssh' });
        expect(publicKey).toBeInstanceOf(SshPublicKey);

        // Verify signature using the new SshSignature.verify method
        const isValid = await sshSignature.verify(data, publicKey as SshPublicKey);
        expect(isValid).toBe(true);
        expect(isValid).toBe(true);
      } finally {
        cleanupTempFiles(privFile, `${privFile}.pub`, dataFile, sigFile);
      }
    });
  });

  // Test: Module signs, ssh-keygen verifies
  algorithms.forEach(algo => {
    it(`should create signature with SSH.sign and verify with ssh-keygen (${algo.name})`, async () => {
      const pubFile = join(
        tmpDirPath,
        `ssh-test-pub-mod-${algo.name.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}.pub`,
      );
      const dataFile = join(
        tmpDirPath,
        `ssh-test-data-mod-${algo.name.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}`,
      );
      const sigFile = `${dataFile}.sig`;
      const allowedSignersFile = join(
        tmpDirPath,
        `ssh-test-allowed-signers-${algo.name.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}`,
      );

      try {
        // Create key pair in module
        const keyPair = await SSH.createKeyPair(algo.moduleType);

        // Export public key to SSH format
        const publicSsh = `${await keyPair.publicKey.toSSH()} test@example.com`;
        writeFileSync(pubFile, `${publicSsh}\n`);

        // Create data file
        const data = new Uint8Array([10, 20, 30, 40, 50]);
        writeFileSync(dataFile, data);

        // Sign data using SSH.sign (SSH SIGNATURE format for ssh-keygen -Y verify compatibility)
        const signature = await SSH.sign(algo.sigAlgo, keyPair.privateKey, data, {
          format: 'ssh-signature',
          namespace: 'file',
        });
        const signatureText = signature.toText();
        writeFileSync(sigFile, signatureText);

        // Create allowed signers file for ssh-keygen verification
        const allowedSignersContent = `test ${await keyPair.publicKey.toSSH()}`;
        writeFileSync(allowedSignersFile, allowedSignersContent);

        // First verify with our own implementation
        const isValidInternal = await signature.verify(data, keyPair.publicKey);
        expect(isValidInternal).toBe(true);

        // Verify with ssh-keygen using proper stdin piping
        // ssh-keygen -Y verify reads data from stdin, not from file argument
        const { execSync } = await import('child_process');
        const verifyCommand = `cat "${dataFile}" | ssh-keygen -Y verify -f "${allowedSignersFile}" -I test -n file -s "${sigFile}"`;

        try {
          execSync(verifyCommand, { stdio: 'pipe', encoding: 'utf8' });
          // If no error, the signature is valid
        } catch (error: any) {
          // If ssh-keygen verification fails, the test should fail
          throw new Error(`ssh-keygen verification failed for ${algo.name}: ${error.message}`);
        }
      } finally {
        cleanupTempFiles(pubFile, dataFile, sigFile, allowedSignersFile);
      }
    });
  });
});
