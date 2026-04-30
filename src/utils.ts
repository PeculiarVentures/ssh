import { hex } from '@peculiar/utils/encoding';
import type { SshKeyType } from './types';

// Reusable TextEncoder and TextDecoder instances
export const encoder = new TextEncoder();
export const decoder = new TextDecoder();

/**
 * Detect SSH key type from PKCS#8 or SPKI DER data
 */
export function detectKeyType(data: Uint8Array): SshKeyType | null {
  try {
    // Basic ASN.1 parsing to extract OID
    if (data.length < 10 || data[0] !== 0x30) {
      return null;
    }

    let offset = 2;
    if (data[1] >= 128) {
      const lengthBytes = data[1] & 0x7f;
      offset += lengthBytes;
    }

    // For PKCS#8, skip version (INTEGER)
    if (data[offset] === 0x02) {
      offset++;
      const intLength = data[offset];
      offset += 1 + intLength;
    }

    // Now at AlgorithmIdentifier SEQUENCE
    if (data[offset] !== 0x30) {
      return null;
    }

    offset += 2;

    // Read OID
    if (data[offset] !== 0x06) {
      return null;
    }

    offset++;
    const oidLength = data[offset];
    offset++;

    const oid = data.slice(offset, offset + oidLength);
    const oidHex = hex.encode(oid);

    // Map OIDs to SSH key types
    switch (oidHex) {
      case '2a864886f70d010101': // RSA
        return 'ssh-rsa';
      case '2b6570': // Ed25519
        return 'ssh-ed25519';
      case '2a8648ce3d0201': // EC Public Key (need to check curve)
        // For EC keys, we need to read the curve OID
        // Skip to parameters (next OID after algorithm OID)
        if (data[offset + oidLength] === 0x06) {
          const curveOidLength = data[offset + oidLength + 1];
          const curveOid = data.slice(
            offset + oidLength + 2,
            offset + oidLength + 2 + curveOidLength,
          );
          const curveOidHex = hex.encode(curveOid);

          switch (curveOidHex) {
            case '2a8648ce3d030107': // P-256
              return 'ecdsa-sha2-nistp256';
            case '2b81040022': // P-384
              return 'ecdsa-sha2-nistp384';
            case '2b81040023': // P-521
              return 'ecdsa-sha2-nistp521';
          }
        }
        return null;
      default:
        return null;
    }
  } catch {
    return null;
  }
}
