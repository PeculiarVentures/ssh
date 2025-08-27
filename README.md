# @peculiar/ssh

A TypeScript library for working with SSH keys and certificates in both Node.js and browsers, built on top of WebCrypto. Provides parsing, serialization, conversion (SPKI/PKCS8 ↔ SSH), and certificate signing/verification with an extensible algorithm registry.

## Features

- 🔐 SSH key format conversion (SSH ↔ WebCrypto SPKI/PKCS8)
- 📜 SSH certificate parsing and serialization
- ✅ Certificate signing and verification
- 🔧 Extensible algorithm registry
- 🌐 Browser and Node.js support
- 📦 Zero dependencies (uses built-in WebCrypto)

## Installation

```bash
npm install @peculiar/ssh
```

## Development

### Prerequisites

- Node.js 18+
- npm or yarn

### Setup

```bash
# Install dependencies
npm install

# Run development build
npm run build

# Run tests
npm test

# Run linting
npm run lint

# Format code
npm run format
```

### Available Scripts

- `npm run build` - Build the library
- `npm run type-check` - Run TypeScript type checking
- `npm test` - Run tests with Vitest
- `npm run test:coverage` - Run tests with coverage
- `npm run lint` - Run ESLint
- `npm run lint:fix` - Fix ESLint issues
- `npm run format` - Format code with Prettier
- `npm run clean` - Clean build artifacts

## Project Structure

```text
src/
├── index.ts         # Main entry point
├── crypto.ts        # Crypto provider utilities
├── registry.ts      # Algorithm registry
├── wire/            # Low-level SSH structures
├── key/             # High-level key abstractions
└── cert/            # Certificate handling
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite: `npm test`
6. Run linting: `npm run lint`
7. Submit a pull request

## License

ISC
