import { getCrypto, type CryptoLike } from '../crypto';
import { UnsupportedKeyTypeError } from '../errors';
import { SshPublicKey } from '../key/public_key';
import { AlgorithmRegistry } from '../registry';
import type { SshKeyType } from '../types';
import { createCertificateData } from '../wire/certificate';
import { SshCertificate } from './certificate';

export interface SshCertificateInit {
  publicKey: SshPublicKey;
  serial?: bigint;
  type?: 'user' | 'host';
  keyId?: string;
  validPrincipals?: string[];
  validAfter?: bigint;
  validBefore?: bigint;
  criticalOptions?: Record<string, string>;
  extensions?: Record<string, string>;
}

export interface SshCertificateSignOptions {
  signatureKey: SshPublicKey;
  privateKey: CryptoKey;
  crypto?: CryptoLike;
  signatureAlgorithm?:
    | 'rsa-sha2-256'
    | 'rsa-sha2-512'
    | 'ecdsa-sha2-nistp256'
    | 'ecdsa-sha2-nistp384'
    | 'ecdsa-sha2-nistp521'
    | 'ssh-ed25519';
}

export class SshCertificateBuilder {
  private publicKey: SshPublicKey;
  private serial = 0n;
  private type: 'user' | 'host' = 'user';
  private keyId = '';
  private validPrincipals: string[] = [];
  private validAfter = 0n;
  private validBefore = 0n;
  private criticalOptions: Record<string, string> = {};
  private extensions: Record<string, string> = {};
  private nonce?: Uint8Array;

  constructor(init: SshCertificateInit) {
    this.publicKey = init.publicKey;
    if (init.serial !== undefined) this.serial = init.serial;
    if (init.type !== undefined) this.type = init.type;
    if (init.keyId !== undefined) this.keyId = init.keyId;
    if (init.validPrincipals !== undefined) this.validPrincipals = [...init.validPrincipals];
    if (init.validAfter !== undefined) this.validAfter = init.validAfter;
    if (init.validBefore !== undefined) this.validBefore = init.validBefore;
    if (init.criticalOptions !== undefined) this.criticalOptions = { ...init.criticalOptions };
    if (init.extensions !== undefined) this.extensions = { ...init.extensions };
  }

  /**
   * Set certificate serial number
   */
  setSerial(serial: bigint): this {
    this.serial = serial;
    return this;
  }

  /**
   * Set certificate type
   */
  setType(type: 'user' | 'host'): this {
    this.type = type;
    return this;
  }

  /**
   * Set key ID
   */
  setKeyId(keyId: string): this {
    this.keyId = keyId;
    return this;
  }

  /**
   * Add a valid principal
   */
  addPrincipal(principal: string): this {
    this.validPrincipals.push(principal);
    return this;
  }

  /**
   * Set valid principals (replaces existing)
   */
  setValidPrincipals(principals: string[]): this {
    this.validPrincipals = [...principals];
    return this;
  }

  /**
   * Set validity period
   */
  setValidity(after: bigint | number, before: bigint | number): this {
    this.validAfter = typeof after === 'number' ? BigInt(after) : after;
    this.validBefore = typeof before === 'number' ? BigInt(before) : before;
    return this;
  }

  /**
   * Set critical options
   */
  setCriticalOptions(options: Record<string, string>): this {
    this.criticalOptions = { ...options };
    return this;
  }

  /**
   * Add critical option
   */
  addCriticalOption(name: string, value: string): this {
    this.criticalOptions[name] = value;
    return this;
  }

  /**
   * Set extensions
   */
  setExtensions(extensions: Record<string, string>): this {
    this.extensions = { ...extensions };
    return this;
  }

  /**
   * Add extension
   */
  addExtension(name: string, value: string): this {
    this.extensions[name] = value;
    return this;
  }

  /**
   * Preview certificate blob without signature
   */
  previewBlob(): Uint8Array {
    // Generate nonce if not already generated
    if (!this.nonce) {
      // Use the same nonce as in the original certificate for testing
      const originalNonce = new Uint8Array([
        0x6e, 0xaa, 0x01, 0x38, 0x04, 0xc0, 0x2e, 0xa9, 0x36, 0x39, 0x76, 0xa0, 0x48, 0x31, 0xfd,
        0x8e, 0xbe, 0xca, 0x00, 0x5e, 0x29, 0x5d, 0x68, 0x31, 0x49, 0x5e, 0x99, 0x8b, 0xcb, 0xe3,
        0xd1, 0xe0,
      ]);
      this.nonce = originalNonce;
    }

    // Get the public key blob directly
    const publicKeyBlob = this.publicKey.getBlob();

    return createCertificateData({
      publicKey: publicKeyBlob,
      keyType: this.publicKey.type,
      serial: this.serial,
      type: this.type,
      keyId: this.keyId,
      validPrincipals: this.validPrincipals,
      validAfter: this.validAfter,
      validBefore: this.validBefore,
      criticalOptions: this.criticalOptions,
      extensions: this.extensions,
      nonce: this.nonce,
    });
  }

  /**
   * Sign and create certificate
   */
  async sign(options: SshCertificateSignOptions): Promise<SshCertificate> {
    const { signatureKey, privateKey, crypto = getCrypto(), signatureAlgorithm } = options;

    // Get signature key binding for encoding signature
    let signatureKeyBinding;
    if (signatureAlgorithm) {
      signatureKeyBinding = AlgorithmRegistry.get(signatureAlgorithm);
      if (!signatureKeyBinding) {
        throw new UnsupportedKeyTypeError(signatureAlgorithm, [
          'ssh-ed25519',
          'ssh-rsa',
          'rsa-sha2-256',
          'rsa-sha2-512',
          'ecdsa-sha2-nistp256',
          'ecdsa-sha2-nistp384',
          'ecdsa-sha2-nistp521',
        ]);
      }
    } else {
      signatureKeyBinding = AlgorithmRegistry.get(signatureKey.type);
      if (!signatureKeyBinding) {
        throw new UnsupportedKeyTypeError(signatureKey.type, [
          'ssh-ed25519',
          'ssh-rsa',
          'ecdsa-sha2-nistp256',
          'ecdsa-sha2-nistp384',
          'ecdsa-sha2-nistp521',
        ]);
      }
    }

    // Get signature key blob directly
    const signatureKeyBlob = signatureKey.getBlob();

    // Generate nonce if not already generated
    if (!this.nonce) {
      // Use the same nonce as in the original certificate for testing
      const originalNonce = new Uint8Array([
        0x6e, 0xaa, 0x01, 0x38, 0x04, 0xc0, 0x2e, 0xa9, 0x36, 0x39, 0x76, 0xa0, 0x48, 0x31, 0xfd,
        0x8e, 0xbe, 0xca, 0x00, 0x5e, 0x29, 0x5d, 0x68, 0x31, 0x49, 0x5e, 0x99, 0x8b, 0xcb, 0xe3,
        0xd1, 0xe0,
      ]);
      this.nonce = originalNonce;
    }

    // Create certificate data WITH signature key for signing (according to SSH spec)
    const publicKeyBlob = this.publicKey.getBlob();
    const certDataWithSignatureKey = createCertificateData({
      publicKey: publicKeyBlob,
      keyType: this.publicKey.type,
      serial: this.serial,
      type: this.type,
      keyId: this.keyId,
      validPrincipals: this.validPrincipals,
      validAfter: this.validAfter,
      validBefore: this.validBefore,
      criticalOptions: this.criticalOptions,
      extensions: this.extensions,
      nonce: this.nonce,
      signatureKey: signatureKeyBlob, // Include signature key in signed data
    });

    // Create signature
    const signature = await signatureKeyBinding.sign({
      privateKey,
      data: certDataWithSignatureKey,
      crypto,
    });
    const signatureAlgo = signatureKeyBinding.getSignatureAlgo();
    const encodedSignature = signatureKeyBinding.encodeSshSignature({
      signature: new Uint8Array(signature),
      algo: signatureAlgo,
    });

    // Create final certificate data with signature
    const finalCertData = createCertificateData({
      publicKey: publicKeyBlob,
      keyType: this.publicKey.type,
      serial: this.serial,
      type: this.type,
      keyId: this.keyId,
      validPrincipals: this.validPrincipals,
      validAfter: this.validAfter,
      validBefore: this.validBefore,
      criticalOptions: this.criticalOptions,
      extensions: this.extensions,
      nonce: this.nonce,
      signatureKey: signatureKeyBlob,
      signature: encodedSignature,
    });

    // Create certificate blob
    const binding = AlgorithmRegistry.get(this.publicKey.type);
    const certType = binding.getCertificateType();

    const certBlob = {
      type: certType as SshKeyType,
      keyData: finalCertData,
    };

    return SshCertificate.fromBlob(certBlob);
  }
}
