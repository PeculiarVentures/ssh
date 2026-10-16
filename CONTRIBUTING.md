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

This project uses GitHub Actions:

- **Test** (`.github/workflows/test.yml`) runs on every pull request: lint, format, typecheck, build, exports check, and tests with coverage (uploaded to [Coveralls](https://coveralls.io/github/PeculiarVentures/ssh)).
- **Publish** (`.github/workflows/publish.yml`) runs on every push to `main` and manages releases (see below).

### Releases

Releases are managed by [release-please](https://github.com/googleapis/release-please) (`release-please-config.json`, `.release-please-manifest.json`):

1. On every push to `main`, the **Publish** workflow first runs lint, format, typecheck, tests, and build (the **Test** workflow). Only when they pass does release-please open or update a `chore(release): vX.Y.Z` pull request that bumps `package.json`/`package-lock.json`. The version comes from the commits: a breaking change bumps major, `feat` bumps minor, and `fix`, `perf`, `build`, and `revert` bump patch. Other types do not trigger a release.
2. Merge the release pull request. release-please creates the `vX.Y.Z` tag and a GitHub Release with the notes from the pull request; the workflow then publishes that commit to npm via Trusted Publisher, with provenance, and moves the major tag (for example `v2`) when this is the newest release of that major.

To retry a failed npm publish, run **Publish** manually from the `vX.Y.Z` tag. Set the optional `RELEASE_TOKEN` secret (PAT or GitHub App token) so the Test workflow runs on the release pull request.

Release notes live only in [GitHub Releases](https://github.com/PeculiarVentures/ssh/releases); there is no `CHANGELOG.md`. Only `feat`, `fix`, `perf`, `build`, `revert`, and breaking changes are listed. Force a version with a `Release-As: x.y.z` line in a commit body. To fix the notes for a merged change, add a `BEGIN_COMMIT_OVERRIDE` … `END_COMMIT_OVERRIDE` block with the corrected commit message to that pull request's description; edits to the release pull request description are overwritten when new commits land.

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
npm run coverage
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
