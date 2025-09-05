# Contributing to @peculiar/ssh

Thank you for your interest in contributing to the @peculiar/ssh library! This document provides guidelines and information for contributors.

## Development Setup

### Prerequisites

- Node.js 18.x or higher
- npm or yarn

### Installation

```bash
# Clone the repository
git clone https://github.com/PeculiarVentures/ssh.git
cd ssh

# Install dependencies
npm install

# Run tests
npm test

# Build the project
npm run build
```

## CI/CD

This project uses GitHub Actions for continuous integration and deployment:

- **Testing**: Automated tests run on multiple Node.js versions (18.x, 20.x, 22.x)
- **Code Coverage**: Coverage reports are generated and uploaded to [Coveralls](https://coveralls.io/github/PeculiarVentures/ssh)
- **Linting**: ESLint and Prettier checks ensure code quality
- **Type Checking**: TypeScript compilation checks
- **Release**: Automatic npm publishing and GitHub releases on version tags

### Publishing

To publish a new version:

1. Update version in `package.json`
2. Create and push a git tag: `git tag v1.2.3 && git push origin v1.2.3`
3. GitHub Actions will automatically:
   - Run tests and build
   - Publish to npm
   - Create a GitHub release with auto-generated notes

## Development Workflow

### Code Quality

Before submitting a pull request, ensure:

```bash
# Run linter
npm run lint

# Fix linting issues
npm run lint:fix

# Check code formatting
npm run format:check

# Fix formatting
npm run format

# Type check
npm run build:check

# Run tests
npm test

# Run tests with coverage
npm run test:coverage
```

### Testing

- Write tests for new features in the `src/**/*.spec.ts` files
- Use Vitest as the test runner
- Aim for good test coverage
- Run `npm run test:ui` for interactive test development

### Commit Messages

Use conventional commit format:

```plain
type(scope): description

[optional body]

[optional footer]
```

Types:

- `chore`: Maintenance changes
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Testing
- `ci`: CI/CD changes

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests and quality checks
5. Commit your changes
6. Push to your fork
7. Create a Pull Request

## Code Style

- Use TypeScript for all new code
- Follow ESLint configuration
- Use Prettier for code formatting
- Write JSDoc comments for public APIs
- Use meaningful variable and function names

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.
