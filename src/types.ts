/**
 * Generic dictionary type
 */
export type Dict<T = unknown> = Record<string, T>;

/**
 * Supported SSH key types including certificates
 *
 * Limitations:
 * - Only unencrypted private keys are supported
 * - Certificate validation is basic
 * - Custom key types are not supported
 */
export type SshKeyType =
  | 'ssh-ed25519'
  | 'ssh-rsa'
  | 'ecdsa-sha2-nistp256'
  | 'ecdsa-sha2-nistp384'
  | 'ecdsa-sha2-nistp521'
  | 'ssh-ed25519-cert-v01@openssh.com'
  | 'ssh-rsa-cert-v01@openssh.com'
  | 'ecdsa-sha2-nistp256-cert-v01@openssh.com'
  | 'ecdsa-sha2-nistp384-cert-v01@openssh.com'
  | 'ecdsa-sha2-nistp521-cert-v01@openssh.com';

/**
 * SSH signature algorithms
 * Note: ssh-rsa is deprecated in favor of rsa-sha2-* variants
 */
export type SshSignatureAlgo =
  | 'ssh-ed25519'
  | 'rsa-sha2-256'
  | 'rsa-sha2-512'
  | 'ecdsa-sha2-nistp256'
  | 'ecdsa-sha2-nistp384'
  | 'ecdsa-sha2-nistp521';

/**
 * Export formats supported by the library
 */
export type ExportFormat = 'ssh' | 'spki' | 'pkcs8';

/**
 * Hash algorithms supported for RSA signatures
 */
export type HashAlgorithm = 'SHA-256' | 'SHA-512';

/**
 * Abstract base class for all SSH objects
 */
export abstract class SshObject {
  /** SSH object type */
  abstract readonly type: string;
  /** Export to SSH format */
  abstract toSSH(): Promise<string>;
}
