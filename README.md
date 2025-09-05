# @peculiar/ssh

A TypeScript library for working with SSH keys and certificates in both Node.js and browsers, built on top of WebCrypto. Provides parsing, serialization, conversion (SPKI/PKCS8 ↔ SSH), and certificate signing/verification with an extensible algorithm registry.

## Features

* 🔑 Generate RSA, ECDSA, and Ed25519 keys
* 🔐 Convert between SSH and WebCrypto formats (SPKI / PKCS8)
* ✍️ Create and verify SSH signatures
* 📜 Parse and build SSH certificates
* 🌐 Works in both browsers and Node.js

## Installation

```bash
npm install @peculiar/ssh
```

## Quick Start

### Generate Keys

```ts
import { SSH } from '@peculiar/ssh';

// RSA 2048
const rsa = await SSH.createKeyPair({ name: 'rsa', modulusLength: 2048 });

// Ed25519
const ed = await SSH.createKeyPair('ed25519');

// ECDSA P-256
const ec = await SSH.createKeyPair('ecdsa-p256');
```

### Export and Import

```ts
// Export to SSH format
const sshPublic = await rsa.publicKey.toSSH();

// Import from SSH format
const imported = await SSH.import(sshPublic);
```

### Signing and Verifying

```ts
const data = new Uint8Array([1, 2, 3]);

// Create SSH signature
const signature = await SSH.sign('ssh-ed25519', ed.privateKey, data, {
  format: 'ssh-signature',
});

// Verify SSH signature
const isValid = await SSH.verify(ed.publicKey, signature, data);
console.log('Signature valid:', isValid);
```

### Certificates

```ts
// Create a certificate
const cert = await SSH.createCertificate(ed.publicKey)
  .setKeyId('user@example.com')
  .addPrincipal('user@example.com')
  .setType('user')
  .setValidity(Date.now(), Date.now() + 365*24*60*60*1000)
  .sign({
    signatureKey: rsa.publicKey,
    privateKey: await rsa.privateKey.toWebCrypto(),
  });

// Verify certificate
const valid = await cert.verify(rsa.publicKey);
```

## Supported Algorithms

* **RSA** - Key sizes: 2048, 3072, 4096 bits with SHA-256/SHA-512 hash selection at signing
* **Ed25519** - Modern elliptic curve signature scheme
* **ECDSA** - P-256, P-384, P-521 curves with SHA-256/SHA-384/SHA-512

## Platform Support

This library works in all modern browsers that support WebCrypto API and in Node.js. Here's the compatibility matrix:

| Feature | Chrome | Edge | Firefox | Safari | Opera | Chrome Android | Firefox Android | Safari iOS | Node.js |
|---------|--------|------|---------|--------|-------|----------------|-----------------|------------|---------|
| **WebCrypto API** | 37+ | 79+ | 34+ | 7+ | 24+ | 37+ | 34+ | 7+ | 15.0+ |
| **RSA, ECDSA** | 37+ | 79+ | 34+ | 7+ | 24+ | 37+ | 34+ | 7+ | 15.0+ |
| **Ed25519** | 137+ | 137+ | 129+ | 17+ | 121+ | 137+ | 129+ | 17+ | 16.17+ |

For older browsers, you may need to provide a WebCrypto polyfill.

**Note:** Ed25519 support was added to major browsers relatively recently. For broader compatibility, consider using ECDSA or RSA algorithms.

## License

MIT License - see LICENSE file for details.
