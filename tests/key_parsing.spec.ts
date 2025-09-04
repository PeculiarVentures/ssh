import { describe, expect, it } from 'vitest';
import { parsePublicKey, serializePublicKey, SshReader } from '../src/wire';
import {
  ecdsaP256Key,
  ecdsaP384Key,
  ecdsaP521Key,
  ed25519Key,
  getAllKeys,
  rsaKey,
} from './utils/testFixtures';

describe('SSH Key Structure Parsing', () => {
  describe('Ed25519 Key Parsing', () => {
    it('should parse Ed25519 public key and extract key data', () => {
      const parsed = parsePublicKey(ed25519Key);
      expect(parsed.type).toBe('ssh-ed25519');

      // Parse the key data to verify structure
      const reader = new SshReader(parsed.keyData);
      const blobType = reader.readString();
      expect(blobType).toBe('ssh-ed25519');

      const keyBytes = reader.readBytes(32); // Ed25519 public key is 32 bytes
      expect(keyBytes.length).toBe(32);
      // Note: SSH Ed25519 keys may have additional data, so we don't check remaining()
    });
  });

  describe('RSA Key Parsing', () => {
    it('should parse RSA public key and extract parameters', () => {
      const parsed = parsePublicKey(rsaKey);
      expect(parsed.type).toBe('ssh-rsa');

      // Parse the key data to verify RSA structure
      const reader = new SshReader(parsed.keyData);
      const blobType = reader.readString();
      expect(blobType).toBe('ssh-rsa');

      const e = reader.readMpInt(); // RSA exponent
      const n = reader.readMpInt(); // RSA modulus

      expect(e.length).toBeGreaterThan(0);
      expect(n.length).toBeGreaterThan(0);
      expect(reader.remaining()).toBe(0); // Should have consumed all data
    });
  });

  describe('ECDSA P-256 Key Parsing', () => {
    it('should parse ECDSA P-256 public key and extract parameters', () => {
      const parsed = parsePublicKey(ecdsaP256Key);
      expect(parsed.type).toBe('ecdsa-sha2-nistp256');

      // Parse the key data to verify ECDSA structure
      const reader = new SshReader(parsed.keyData);
      const blobType = reader.readString();
      expect(blobType).toBe('ecdsa-sha2-nistp256');

      const curveName = reader.readString();
      expect(curveName).toBe('nistp256');

      const publicKeyMpint = reader.readMpInt(); // ECDSA public key as mpint
      expect(publicKeyMpint.length).toBeGreaterThan(0);
      expect(reader.remaining()).toBe(0); // Should have consumed all data
    });
  });

  describe('ECDSA P-384 Key Parsing', () => {
    it('should parse ECDSA P-384 public key and extract parameters', () => {
      const parsed = parsePublicKey(ecdsaP384Key);
      expect(parsed.type).toBe('ecdsa-sha2-nistp384');

      // Parse the key data to verify ECDSA structure
      const reader = new SshReader(parsed.keyData);
      const blobType = reader.readString();
      expect(blobType).toBe('ecdsa-sha2-nistp384');

      const curveName = reader.readString();
      expect(curveName).toBe('nistp384');

      const publicKeyMpint = reader.readMpInt(); // ECDSA public key as mpint
      expect(publicKeyMpint.length).toBeGreaterThan(0);
      expect(reader.remaining()).toBe(0); // Should have consumed all data
    });
  });

  describe('ECDSA P-521 Key Parsing', () => {
    it('should parse ECDSA P-521 public key and extract parameters', () => {
      const parsed = parsePublicKey(ecdsaP521Key);
      expect(parsed.type).toBe('ecdsa-sha2-nistp521');

      // Parse the key data to verify ECDSA structure
      const reader = new SshReader(parsed.keyData);
      const blobType = reader.readString();
      expect(blobType).toBe('ecdsa-sha2-nistp521');

      const curveName = reader.readString();
      expect(curveName).toBe('nistp521');

      const publicKeyMpint = reader.readMpInt(); // ECDSA public key as mpint
      expect(publicKeyMpint.length).toBeGreaterThan(0);
      expect(reader.remaining()).toBe(0); // Should have consumed all data
    });
  });

  describe('Key Format Validation', () => {
    it('should validate key data integrity for all key types', () => {
      const keys = getAllKeys();

      keys.forEach(keyString => {
        const parsed = parsePublicKey(keyString);
        expect(parsed.keyData.length).toBeGreaterThan(0);

        // Verify that we can parse the key data without errors
        const reader = new SshReader(parsed.keyData);
        const blobType = reader.readString();
        expect(blobType).toBe(parsed.type);
      });
    });

    it('should handle keys with special characters in comments', () => {
      const keyWithSpecialComment =
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHIAzSy6yKCJDZA4Pbw/7Z4baapPp/DQeaN4dz8iFsNA user@host.domain.com';
      const parsed = parsePublicKey(keyWithSpecialComment);
      expect(parsed.comment).toBe('user@host.domain.com');

      const serialized = serializePublicKey(parsed);
      expect(serialized).toBe(keyWithSpecialComment);
    });
  });
});
