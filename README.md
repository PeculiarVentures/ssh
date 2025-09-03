# @peculiar/ssh

A TypeScript library for working with SSH keys and certificates in both Node.js and browsers, built on top of WebCrypto. Provides parsing, serialization, conversion (SPKI/PKCS8 ↔ SSH), and certificate signing/verification with an extensible algorithm registry.

## Features

- 🔐 **SSH key format conversion** - SSH ↔ WebCrypto SPKI/PKCS8
- 📜 **SSH certificate parsing and creation** - Full certificate lifecycle support
- ✅ **Certificate signing and verification** - Built-in cryptographic operations
- 🔧 **Extensible algorithm registry** - Support for RSA, Ed25519, ECDSA algorithms
- 🌐 **Universal compatibility** - Works in browsers and Node.js
- 📦 **Zero external dependencies** - Uses built-in WebCrypto API
- 🚀 **Modern unified API** - Simple and intuitive interface

## Supported Algorithms

- **RSA** - Key sizes: 2048, 3072, 4096 bits with SHA-256/SHA-512 hash selection at signing
- **Ed25519** - Modern elliptic curve signature scheme
- **ECDSA** - P-256, P-384, P-521 curves with SHA-256/SHA-384/SHA-512

## Installation

```bash
npm install @peculiar/ssh
```

## Quick Start

### � New Unified API (Recommended)

```typescript
import { SSH } from '@peculiar/ssh';

// Auto-detect and import any SSH format
const privateKey = await SSH.import(sshPrivateKeyString);
const publicKey = await SSH.import(sshPublicKeyString); 
const certificate = await SSH.import(sshCertificateString);

// Create new key pairs
const { privateKey, publicKey } = await SSH.createKeyPair('ed25519');

// RSA with custom key size
const rsa4096 = await SSH.createKeyPair({ name: 'rsa', modulusLength: 4096 });

// ECDSA with custom curve
const ecdsa384 = await SSH.createKeyPair({ name: 'ecdsa-p384' });
const ecdsa521 = await SSH.createKeyPair({ name: 'ecdsa-p521' });

// Simple exports with intuitive names
const sshFormat = await publicKey.toSSH();
const spkiFormat = await publicKey.toSPKI();
const webCryptoKey = await publicKey.toWebCrypto();

// Easy certificate creation
const certificate = await SSH.createCertificate(publicKey)
  .setKeyId('user@example.com')
  .addPrincipal('user@example.com')
  .setValidity(Date.now(), Date.now() + 365*24*60*60*1000)
  .sign({ signatureKey: caPublicKey, privateKey: caPrivateKey });
```

### 🔑 Flexible Key Generation

The new API supports both string and object algorithm specifications:

```typescript
// String algorithms (backward compatible)
const ed25519 = await SSH.createKeyPair('ed25519');
const rsa = await SSH.createKeyPair('rsa');
const ecdsa = await SSH.createKeyPair('ecdsa-p256');

// Object algorithms with parameters
const rsa2048 = await SSH.createKeyPair({ name: 'rsa', modulusLength: 2048 });
const rsa3072 = await SSH.createKeyPair({ name: 'rsa', modulusLength: 3072 });
const rsa4096 = await SSH.createKeyPair({ name: 'rsa', modulusLength: 4096 });
const ecdsa384 = await SSH.createKeyPair({ name: 'ecdsa-p384' });
const ecdsa521 = await SSH.createKeyPair({ name: 'ecdsa-p521' });
```

**Supported RSA key sizes:** 2048, 3072, 4096 bits  
**Hash selection:** Available at signing/verification time for RSA (SHA-256, SHA-512)

### 📚 Working with Keys

```typescript
import { SSH, SshPrivateKey, SshPublicKey } from '@peculiar/ssh';

// Import SSH private key (auto-detects OpenSSH or PKCS#8)
const privateKey = await SSH.import(privateKeyData);

// Import SSH public key  
const publicKey = await SSH.import(publicKeyData);

// Generate new key pair
const { privateKey, publicKey } = await SSH.createKeyPair('rsa');

// Export in different formats
const sshPrivateKey = await privateKey.toSSH();        // SSH format
const pkcs8Data = await privateKey.toPKCS8();          // PKCS#8 binary
const webCrypto = privateKey.toWebCrypto();            // WebCrypto key

// Sign and verify
const signature = await privateKey.signData(data);
const isValid = await publicKey.verifySignature(data, signature);

// RSA signature with custom hash (SHA-256 is default)
const sha256Signature = await privateKey.signDataWithHash(data, 'SHA-256');
const sha256Valid = await publicKey.verifySignatureWithHash(data, sha256Signature, 'SHA-256');

// RSA signature with SHA-512
const sha512Signature = await privateKey.signDataWithHash(data, 'SHA-512');
const sha512Valid = await publicKey.verifySignatureWithHash(data, sha512Signature, 'SHA-512');

// Get public key from private key
const pubKey = await privateKey.getPublicKey();
```

### 🏆 Working with Certificates  

```typescript
import { SSH, SshCertificate } from '@peculiar/ssh';

// Import certificate
const cert = await SSH.import(certificateString);

// Access certificate properties (synchronous after import!)
console.log('Key ID:', cert.keyId);
console.log('Principals:', cert.principals);
console.log('Type:', cert.certType);
console.log('Is valid:', cert.isValid);

// Verify certificate
const isValidCert = await cert.verify(caPublicKey);

// Create new certificate
const builder = SSH.createCertificate(userPublicKey)
  .setKeyId('john.doe@company.com')
  .addPrincipal('john.doe@company.com')
  .addPrincipal('jdoe')
  .setType('user')
  .setValidity(
    BigInt(Math.floor(Date.now() / 1000)), // Valid from now
    BigInt(Math.floor(Date.now() / 1000) + 31536000) // Valid for 1 year
  )
  .setCriticalOptions({ 'force-command': '/bin/bash' })
  .setExtensions({ 'permit-agent-forwarding': '' });

const certificate = await builder.sign({
  signatureKey: caPublicKey,
  privateKey: caPrivateKey
});
```

### 🔧 Advanced Usage

```typescript
// Direct class usage (classic API)
import { SshPrivateKey, SshPublicKey, SshCertificate } from '@peculiar/ssh';

// Import specific formats
const privateKey = await SshPrivateKey.importPrivateFromSsh(sshKey);
const publicKey = await SshPublicKey.importPublicFromSsh(sshKey);
const certificate = await SshCertificate.fromText(certText);

// Algorithm registry (for custom implementations)
import { AlgorithmRegistry } from '@peculiar/ssh';
const binding = AlgorithmRegistry.get('ssh-ed25519');
```

## Platform Support

This library works in all modern browsers that support WebCrypto API and in Node.js. Here's the compatibility matrix:

| Feature | Chrome | Edge | Firefox | Safari | Opera | Chrome Android | Firefox Android | Safari iOS | Node.js |
|---------|--------|------|---------|--------|-------|----------------|-----------------|------------|---------|
| **WebCrypto API** | 37+ | 79+ | 34+ | 7+ | 24+ | 37+ | 34+ | 7+ | 15.0+ |
| **RSA, ECDSA** | 37+ | 79+ | 34+ | 7+ | 24+ | 37+ | 34+ | 7+ | 15.0+ |
| **Ed25519** | 137+ | 137+ | 129+ | 17+ | 121+ | 137+ | 129+ | 17+ | 16.17+ |

For older browsers, you may need to provide a WebCrypto polyfill.

**Note:** Ed25519 support was added to major browsers relatively recently. For broader compatibility, consider using ECDSA or RSA algorithms.

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our repository.

## License

MIT License - see LICENSE file for details.
