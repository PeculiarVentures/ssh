# Contributing to @peculiar/ssh

Thank you for your interest in contributing to the @peculiar/ssh library! This document provides guidelines and information for contributors.

## Development Setup

### Prerequisites

- Node.js 22.18 or higher (for development; the published package supports Node.js 20+)
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

- **Testing**: Automated tests run on Node.js 22.x
- **Code Coverage**: Coverage reports are generated and uploaded to [Coveralls](https://coveralls.io/github/PeculiarVentures/ssh)
- **Linting**: oxlint and oxfmt checks ensure code quality
- **Type Checking**: TypeScript compilation checks
- **Release**: Version bump PRs with generated changelog; npm publishing, tags, and GitHub releases on merge

### Publishing

Releases are done in two steps:

1. Run the **Version Bump** workflow (Actions → Version Bump → Run workflow) and pick `patch`, `minor`, or `major`.
   It opens a `chore(release): vX.Y.Z` pull request that bumps `package.json`/`package-lock.json` and prepends a
   `CHANGELOG.md` section generated with `conventional-changelog -p angular`.
2. Review the version and changelog, then merge the pull request. The **Publish** workflow then:
   - Runs lint, format, typecheck, tests, and build
   - Publishes to npm via Trusted Publisher
   - Pushes the `vX.Y.Z` tag and moves the major tag (e.g. `v1`)
   - Creates a GitHub release from the matching `CHANGELOG.md` section

Publish runs only when no GitHub release exists for the current version, so a failed run can be re-run safely.
Set the optional `RELEASE_TOKEN` secret (PAT or GitHub App token) so CI runs on the version bump pull request.

Only `feat`, `fix`, `perf`, and breaking changes appear in the changelog. If a release contains none of them, edit
the new `CHANGELOG.md` section in the version bump pull request before merging; Publish fails on an empty section.

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
npm run typecheck

# Run tests
npm test

# Run tests with coverage
npm run test:coverage
```

### Testing

- Write tests for new features in the `src/**/*.spec.ts` files
- Use Vitest as the test runner
- Aim for good test coverage
- Run `npm run test:watch` for interactive test development

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
- Follow the oxlint configuration (`.oxlintrc.json`)
- Use oxfmt for code formatting (`.oxfmtrc.json`)
- Write JSDoc comments for public APIs
- Use meaningful variable and function names

## License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.
