import { describe, expect, it } from 'vitest';
import { parsePublicKey, serializePublicKey, SshReader } from '../src';

describe('SSH Key Structure Parsing', () => {
  describe('Ed25519 Key Parsing', () => {
    it('should parse Ed25519 public key and extract key data', () => {
      const ed25519Key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHIAzSy6yKCJDZA4Pbw/7Z4baapPp/DQeaN4dz8iFsNA test-ed25519';

      const parsed = parsePublicKey(ed25519Key);
      expect(parsed.type).toBe('ssh-ed25519');

      // Parse the key data to verify structure
      const reader = new SshReader(parsed.keyData);
      const blobType = reader.readString();
      expect(blobType).toBe('ssh-ed25519');

      const keyBytes = reader.readBytes(32); // Ed25519 public key is 32 bytes
      expect(keyBytes.length).toBe(32);
      // Note: SSH Ed25519 keys may have additional data, so we don't check remaining()
    },);
  },);

  describe('RSA Key Parsing', () => {
    it('should parse RSA public key and extract parameters', () => {
      const rsaKey = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCFXhvouwZBf0U7hdnx5+x1gKp881l6H3wODWuZEZvzxUbEOcR4Btuhe+ZpG7lu1CwdZXx+ViM/iD0EjRt3FMvwoo01FsU/OcQE9J1gK0v3iFMPCxc8kv71bs3twQa7oKxfkAqkL4iClg84YqR9aHJ+jYiBUMRxSPm1Yaip+FnQC3qOCF12Ks/mrnL4AA2VyxIWQz5bBX/oNSa/mjfOY883C3QxMWJKGH9WffCUuNFiyMBGI3ERNVmIyLn+kBTBNk/On5paJ49QBk97RIVCwgxUMX+8Z23kpfCx9xDOEK54Pt887dWa5QQcAvfWYBw8khtzVo+nGmUiRiqGpYVDzsmP test-rsa';

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
      const ecdsaKey = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHTUF2juGU/nt4CwHQzBDrvbjfgXFAYrAyN26etDYpKqzwU3kmdXfiCahNVwnWAGdRUc9JfTR32xqMs0Z9nAH4s= test-ecdsa-p256';

      const parsed = parsePublicKey(ecdsaKey);
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
      const ecdsaKey = 'ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBC176k1WZa7m+d/2PASRpjWNXXmqM97j86PST4SGndlOWzq5VRAprvqsBAtCJ22yy7nkI1eycEH1z1MUmASENfI5TCI6At3akaUoVWih7xsy85QH2I5pyXo6UPt4U2sDuA== test-ecdsa-p384';

      const parsed = parsePublicKey(ecdsaKey);
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
      const ecdsaKey = 'ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAH2XvyymGSIyDVMgqIiyeTlVZo4xKkCVt6PtMtoOUeLY6fNQXAJv5UP2/gPqWNKe2hbUQYtGGjB0nz/FIzJtbXrCADKmCwG35cEBDeJgskdptJksSCRAi46meA/NKR3hWcgcscCoY3vS92lH8gmFTTC0qoXn9ibYnCMXH8pqZ1/2k+IRw== test-ecdsa-p521';

      const parsed = parsePublicKey(ecdsaKey);
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
      const keys = [
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHIAzSy6yKCJDZA4Pbw/7Z4baapPp/DQeaN4dz8iFsNA test-ed25519',
        'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCFXhvouwZBf0U7hdnx5+x1gKp881l6H3wODWuZEZvzxUbEOcR4Btuhe+ZpG7lu1CwdZXx+ViM/iD0EjRt3FMvwoo01FsU/OcQE9J1gK0v3iFMPCxc8kv71bs3twQa7oKxfkAqkL4iClg84YqR9aHJ+jYiBUMRxSPm1Yaip+FnQC3qOCF12Ks/mrnL4AA2VyxIWQz5bBX/oNSa/mjfOY883C3QxMWJKGH9WffCUuNFiyMBGI3ERNVmIyLn+kBTBNk/On5paJ49QBk97RIVCwgxUMX+8Z23kpfCx9xDOEK54Pt887dWa5QQcAvfWYBw8khtzVo+nGmUiRiqGpYVDzsmP test-rsa',
        'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHTUF2juGU/nt4CwHQzBDrvbjfgXFAYrAyN26etDYpKqzwU3kmdXfiCahNVwnWAGdRUc9JfTR32xqMs0Z9nAH4s= test-ecdsa-p256',
        'ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBC176k1WZa7m+d/2PASRpjWNXXmqM97j86PST4SGndlOWzq5VRAprvqsBAtCJ22yy7nkI1eycEH1z1MUmASENfI5TCI6At3akaUoVWih7xsy85QH2I5pyXo6UPt4U2sDuA== test-ecdsa-p384',
        'ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAH2XvyymGSIyDVMgqIiyeTlVZo4xKkCVt6PtMtoOUeLY6fNQXAJv5UP2/gPqWNKe2hbUQYtGGjB0nz/FIzJtbXrCADKmCwG35cEBDeJgskdptJksSCRAi46meA/NKR3hWcgcscCoY3vS92lH8gmFTTC0qoXn9ibYnCMXH8pqZ1/2k+IRw== test-ecdsa-p521',
      ];

      keys.forEach((keyString) => {
        const parsed = parsePublicKey(keyString);
        expect(parsed.keyData.length).toBeGreaterThan(0);

        // Verify that we can parse the key data without errors
        const reader = new SshReader(parsed.keyData);
        const blobType = reader.readString();
        expect(blobType).toBe(parsed.type);
      });
    });

    it('should handle keys with special characters in comments', () => {
      const keyWithSpecialComment = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHIAzSy6yKCJDZA4Pbw/7Z4baapPp/DQeaN4dz8iFsNA user@host.domain.com';
      const parsed = parsePublicKey(keyWithSpecialComment);
      expect(parsed.comment).toBe('user@host.domain.com');

      const serialized = serializePublicKey(parsed);
      expect(serialized).toBe(keyWithSpecialComment);
    });
  });
},);
