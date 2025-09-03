/**
 * Custom error classes for better error handling and debugging
 */

/**
 * Base class for SSH-related errors
 */
export class SshError extends Error {
  constructor(
    message: string,
    public readonly code?: string,
  ) {
    super(message);
    this.name = this.constructor.name;

    // Maintains proper stack trace for where our error was thrown (Node.js only)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * Thrown when an unsupported algorithm is encountered
 */
export class UnsupportedAlgorithmError extends SshError {
  constructor(algorithm: string, supportedAlgorithms?: string[]) {
    const supported = supportedAlgorithms ? ` Supported: ${supportedAlgorithms.join(', ')}` : '';
    super(`Unsupported algorithm: ${algorithm}.${supported}`, 'UNSUPPORTED_ALGORITHM');
  }
}

/**
 * Thrown when an invalid format is encountered
 */
export class InvalidFormatError extends SshError {
  constructor(format: string, expectedFormat?: string) {
    const expected = expectedFormat ? ` Expected: ${expectedFormat}` : '';
    super(`Invalid format: ${format}.${expected}`, 'INVALID_FORMAT');
  }
}

/**
 * Thrown when SSH key type is unsupported
 */
export class UnsupportedKeyTypeError extends SshError {
  constructor(keyType: string, supportedTypes?: string[]) {
    const supported = supportedTypes ? ` Supported: ${supportedTypes.join(', ')}` : '';
    super(`Unsupported key type: ${keyType}.${supported}`, 'UNSUPPORTED_KEY_TYPE');
  }
}

/**
 * Thrown when SSH private key format is invalid
 */
export class InvalidPrivateKeyFormatError extends SshError {
  constructor(details?: string) {
    const message = details
      ? `Invalid SSH private key format: ${details}`
      : 'Invalid SSH private key format';
    super(message, 'INVALID_PRIVATE_KEY_FORMAT');
  }
}

/**
 * Thrown when encrypted SSH keys are encountered (not yet supported)
 */
export class EncryptedKeyNotSupportedError extends SshError {
  constructor(cipher?: string) {
    const message = cipher
      ? `Encrypted SSH private keys are not supported (cipher: ${cipher})`
      : 'Encrypted SSH private keys are not supported';
    super(message, 'ENCRYPTED_KEY_NOT_SUPPORTED');
  }
}

/**
 * Thrown when key data is invalid or corrupted
 */
export class InvalidKeyDataError extends SshError {
  constructor(details?: string) {
    const message = details ? `Invalid key data: ${details}` : 'Invalid key data';
    super(message, 'INVALID_KEY_DATA');
  }
}

/**
 * Thrown when unexpected end of file/data is encountered
 */
export class UnexpectedEOFError extends SshError {
  constructor(expected?: number, actual?: number) {
    const details =
      expected !== undefined && actual !== undefined
        ? ` Expected ${expected} bytes, got ${actual}`
        : '';
    super(`Unexpected end of data${details}`, 'UNEXPECTED_EOF');
  }
}

/**
 * Thrown when SSH export is not supported for a specific algorithm
 */
export class ExportNotSupportedError extends SshError {
  constructor(algorithm: string, format: string) {
    super(`SSH export to ${format} format not supported for ${algorithm}`, 'EXPORT_NOT_SUPPORTED');
  }
}
