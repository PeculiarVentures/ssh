## [1.1.3](https://github.com/PeculiarVentures/ssh/compare/v1.1.2...v1.1.3) (2026-04-30)

### Bug Fixes

* ECDSA certificate verification ([4056b8c](https://github.com/PeculiarVentures/ssh/commit/4056b8c384f902ed4b4d3899efc9169de61f76bd))

## [1.1.2](https://github.com/PeculiarVentures/ssh/compare/v1.1.1...v1.1.2) (2026-04-24)

### Bug Fixes

* enhance RSA algorithm with non-extractable key handling and hash re-import logic ([5f7b3e2](https://github.com/PeculiarVentures/ssh/commit/5f7b3e2dd9a722b6798c9ff6eef87e4b009ff652)), closes [#1](https://github.com/PeculiarVentures/ssh/issues/1)

## [1.1.1](https://github.com/PeculiarVentures/ssh/compare/v1.1.0...v1.1.1) (2025-10-01)

### Bug Fixes

* export missed types ([2efec5b](https://github.com/PeculiarVentures/ssh/commit/2efec5b0a89ed6f33dc905d71c61ae0301af3251))

# [1.1.0](https://github.com/PeculiarVentures/ssh/compare/v1.0.0...v1.1.0) (2025-10-01)

### Bug Fixes

* improve type detection for PKCS8 and SPKI formats ([3f0cf38](https://github.com/PeculiarVentures/ssh/commit/3f0cf38580b63d5561bcc3faaaaa5f48b6609f10))

### Features

* enhance SshCertificateBuilder with validity input type and default extensions ([375aea5](https://github.com/PeculiarVentures/ssh/commit/375aea5f8eea7ded1de99820074983155144cb67))
* enhance validity date handling in SshCertificateBuilder ([cd7230b](https://github.com/PeculiarVentures/ssh/commit/cd7230b30581a7bbd26a67394a33517f8a30b84c))

# [1.0.0](https://github.com/PeculiarVentures/ssh/compare/83eef65b558a7f36aa5ea456c8533e693577d9d5...v1.0.0) (2025-09-05)

### Bug Fixes

* correct ECDSA P-384/P-521 public key coordinate parsing ([6a758d8](https://github.com/PeculiarVentures/ssh/commit/6a758d871653dc32ba3dcbf774c9816491192b6d))
* enhance format detection logic in detectFormat method for improved accuracy ([5759d37](https://github.com/PeculiarVentures/ssh/commit/5759d37b53883de499e7e7f4f0fab9c1d49f938d))
* enhance RSA signing and verification to handle non-extractable keys and improve algorithm detection ([21542e3](https://github.com/PeculiarVentures/ssh/commit/21542e3d8211124d48b9c1389abbe59727f610fc))
* refactor signature creation to use signatureKeyBinding for improved clarity ([e3ab89c](https://github.com/PeculiarVentures/ssh/commit/e3ab89cf466d6ac2498da0bf85d4903a4c1a5674))
* replace UnsupportedKeyTypeError with InvalidFormatError in parsePublicKey function ([5be4682](https://github.com/PeculiarVentures/ssh/commit/5be4682585f1a82fbace85c81a2f27b43f2d34e0))
* update certificate type format in createCertificateData function ([02a45cf](https://github.com/PeculiarVentures/ssh/commit/02a45cfa50fb2e6ccc45f113647bc2a047b3ca21))
* update signature encoding and decoding to include byte length for improved integrity ([234f2e7](https://github.com/PeculiarVentures/ssh/commit/234f2e71af6c0981bc4d78887f3d7575d3285637))
* update validation logic to use internal validAfter and validBefore properties for improved accuracy ([25d80a3](https://github.com/PeculiarVentures/ssh/commit/25d80a3cc408a74b4049fe15933f569f47690bb2))
* use cached public key for exporting SSH public key blob ([56dbe75](https://github.com/PeculiarVentures/ssh/commit/56dbe753c17d5aa32a25a4f579f73fb8bf300aa2))

### Features

* add custom error classes for improved error handling ([272c805](https://github.com/PeculiarVentures/ssh/commit/272c805e1b827a3aa42f81b3576c2fa2d3249067))
* add ECDSA support to SSH certificates ([369c5fd](https://github.com/PeculiarVentures/ssh/commit/369c5fda74749043a8c0e857f99a6a9a6ac7c614))
* add reserve method to SshWriter for improved buffer management ([affdf22](https://github.com/PeculiarVentures/ssh/commit/affdf22fe9f72a134d9ef2a0b59e74eb737cb6d4))
* Add RSA SHA-512 support for SSH certificates ([7ea1a21](https://github.com/PeculiarVentures/ssh/commit/7ea1a21b87dff7d7a2d810e27aad23b032604847))
* add SSH signature handling with parsing and serialization ([48c97a2](https://github.com/PeculiarVentures/ssh/commit/48c97a23c36f6be8ff1c52462a7f0612e0e2e0fc))
* add thumbprint methods for public keys and SSH objects ([069c103](https://github.com/PeculiarVentures/ssh/commit/069c103a735954c57f80c91b133bdef1bdfbbd6a))
* enhance SSH certificate parsing and serialization with comment support ([4f12ee9](https://github.com/PeculiarVentures/ssh/commit/4f12ee9cdc58e793ba7cc9e010b0b8fdd1ea7b05))
* implement crypto provider and project structure ([2b1f836](https://github.com/PeculiarVentures/ssh/commit/2b1f8361144751e681e4410a5ac20596b376ef0e))
* implement Ed25519 certificate generation and verification ([5bb1a97](https://github.com/PeculiarVentures/ssh/commit/5bb1a9729d8aa9fc5a6a38e9148b473c18382d4e))
* implement getSignatureAlgo method for algorithm bindings and refactor certificate handling ([9e7a633](https://github.com/PeculiarVentures/ssh/commit/9e7a633b91adb4b51519d6396e149735c8c3f916))
* implement importPrivateFromSsh method for ECDSA, Ed25519, and RSA algorithms ([8d95ab9](https://github.com/PeculiarVentures/ssh/commit/8d95ab9015af86d2fbbbbae02943c0510c3173c3))
* implement SSH certificate handling with parsing, serialization, and key retrieval ([ec95fcf](https://github.com/PeculiarVentures/ssh/commit/ec95fcf83429ebe6c84eadeef0db2610cdbf2c3e))
* implement SSH export functionality for private keys across ECDSA, Ed25519, and RSA algorithms ([aa32b4d](https://github.com/PeculiarVentures/ssh/commit/aa32b4df512b195dc6d7fab00acde6b6ed93d12f))
* implement SSH private key import from string and enhance algorithm registry ([5cca856](https://github.com/PeculiarVentures/ssh/commit/5cca856dd90f9f96c398ed0e00ef15f748de9631))
* implement SSH wire format and crypto types, including reader/writer classes ([2ee076c](https://github.com/PeculiarVentures/ssh/commit/2ee076c7e1edcd360408a9dede45e923dc391fde))
* implement SshPrivateKey and SshPublicKey classes ([0486aec](https://github.com/PeculiarVentures/ssh/commit/0486aec4093c49c607191f19a45043224fc9c78e))
* implement unified SSH API ([ddbe55a](https://github.com/PeculiarVentures/ssh/commit/ddbe55aee37f2647001e306aa4054872a312cb24))
* initial project setup ([83eef65](https://github.com/PeculiarVentures/ssh/commit/83eef65b558a7f36aa5ea456c8533e693577d9d5))
* support dynamic parsing of public keys from certificate formats ([baad6ec](https://github.com/PeculiarVentures/ssh/commit/baad6ec46071baadf397187ffc595b2fa47351a5))
