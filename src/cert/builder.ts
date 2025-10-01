import { getCrypto } from '../crypto';
import { SshPublicKey } from '../key/public_key';
import { AlgorithmRegistry } from '../registry';
import type { SshCertificateType, SshKeyType, SshSignatureAlgorithm } from '../types';
import { createCertificateData } from '../wire/certificate';
import { SshCertificate } from './certificate';

export type SshValidityInput = bigint | number | Date;

export interface SshCertificateInit {
  publicKey: SshPublicKey;
  serial?: bigint;
  type?: SshCertificateType;
  keyId?: string;
  validPrincipals?: string[];
  validAfter?: SshValidityInput;
  validBefore?: SshValidityInput;
  criticalOptions?: Record<string, string>;
  extensions?: Record<string, string>;
}

export interface SshCertificateSignOptions {
  signatureKey: SshPublicKey;
  privateKey: CryptoKey;
  crypto?: Crypto;
  signatureAlgorithm?: SshSignatureAlgorithm;
}

export class SshCertificateBuilder {
  private publicKey: SshPublicKey;
  private serial = 0n;
  private type: SshCertificateType = 'user';
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
    if (init.validAfter !== undefined) this.validAfter = this.toBigIntTimestamp(init.validAfter);
    if (init.validBefore !== undefined) this.validBefore = this.toBigIntTimestamp(init.validBefore);
    if (init.criticalOptions !== undefined) this.criticalOptions = { ...init.criticalOptions };
    if (init.extensions !== undefined) this.extensions = { ...init.extensions };
  }

  private toBigIntTimestamp(value: SshValidityInput): bigint {
    if (value instanceof Date) {
      return BigInt(Math.floor(value.getTime() / 1000));
    } else if (typeof value === 'number') {
      return BigInt(value);
    } else {
      return value;
    }
  }

  /**
   * Set certificate serial number
   */
  setSerial(serial: bigint): this {
    this.serial = serial;
    return this;
  }

  /**
   * Set random certificate serial number
   */
  setSerialRandom(bytes: number): this {
    const randomBytes = crypto.getRandomValues(new Uint8Array(bytes));
    let serial = 0n;
    for (const byte of randomBytes) {
      serial = (serial << 8n) | BigInt(byte);
    }
    this.serial = serial;
    return this;
  }

  /**
   * Set certificate type
   */
  setType(type: SshCertificateType): this {
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
  setValidity(after: SshValidityInput, before: SshValidityInput): this {
    this.validAfter = this.toBigIntTimestamp(after);
    this.validBefore = this.toBigIntTimestamp(before);
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
   * Set default extensions for user certificates
   */
  setExtensionsDefault(): this {
    this.extensions = {
      'permit-X11-forwarding': '',
      'permit-agent-forwarding': '',
      'permit-port-forwarding': '',
      'permit-pty': '',
      'permit-user-rc': '',
    };
    return this;
  }

  /**
   * Preview certificate blob without signature
   */
  previewBlob(): Uint8Array {
    // Generate nonce if not already generated
    if (!this.nonce) {
      this.nonce = crypto.getRandomValues(new Uint8Array(32));
    }

    // Get the public key blob directly
    const publicKeyBlob = this.publicKey.getBlob();

    return createCertificateData({
      publicKey: publicKeyBlob,
      keyType: this.publicKey.keyType,
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
    } else {
      signatureKeyBinding = AlgorithmRegistry.get(signatureKey.keyType);
    }

    // Get signature key blob directly
    const signatureKeyBlob = signatureKey.getBlob();

    // Generate nonce if not already generated
    if (!this.nonce) {
      this.nonce = crypto.getRandomValues(new Uint8Array(32));
    }

    // Create certificate data WITH signature key for signing (according to SSH spec)
    const publicKeyBlob = this.publicKey.getBlob();
    const certDataWithSignatureKey = createCertificateData({
      publicKey: publicKeyBlob,
      keyType: this.publicKey.keyType,
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
    const encodedSignature = signatureKeyBinding.encodeSignature({
      signature: new Uint8Array(signature),
      algo: signatureAlgo,
    });

    // Create final certificate data with signature
    const finalCertData = createCertificateData({
      publicKey: publicKeyBlob,
      keyType: this.publicKey.keyType,
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
    const binding = AlgorithmRegistry.get(this.publicKey.keyType);
    const certType = binding.getCertificateType();

    const certBlob = {
      type: certType as SshKeyType,
      keyData: finalCertData,
    };

    return SshCertificate.fromBlob(certBlob);
  }
}
