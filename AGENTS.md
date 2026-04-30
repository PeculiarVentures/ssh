# Project Guidelines

## Scope

These instructions apply to the entire repository.

## Project Context

- This project is a TypeScript library for SSH keys and certificates that targets both Node.js and browser environments.
- Keep public APIs portable. Avoid introducing Node-only behavior into source files unless the existing module already depends on it.
- Prefer focused, minimal changes that match the existing layout in `src/`, with unit tests placed next to the updated module when possible.

## Environment

- Use Node.js 20 or newer. The package declares `"node": ">=20.0.0"` in `package.json`.
- Use npm scripts from `package.json` for validation instead of ad hoc commands when an equivalent script already exists.

## Commit Messages

- Write commit messages in English.
- Follow the Conventional Commits format already documented in `CONTRIBUTING.md` and used in recent history.
- Preferred format: `type(scope): short imperative summary`
- Scope is optional when it does not add value, but use it when the change is localized.
- Keep release-version commits unchanged if the maintainer explicitly needs plain version bumps such as `1.1.2`.

Recent examples from this repository:

- `fix: ECDSA certificate verification`
- `ci(release): specify Node.js version in release workflow`
- `chore(package): update repository field format in package.json`
- `chore(vitest): replace tsconfigPaths plugin with resolve option in Vitest config`
- `fix: export missed types`

Use these types unless the change clearly needs another conventional type:

- `fix`: bug fixes or behavioral corrections
- `feat`: new functionality
- `chore`: maintenance, dependency, or build housekeeping
- `ci`: workflow and automation changes
- `docs`: documentation-only changes
- `test`: test-only changes
- `refactor`: internal restructuring without intended behavior change

## Validation After Code Changes

Run the smallest relevant checks first, then widen only as needed.

Common validation scripts:

- `npm run build:check` — TypeScript type check without emitting files
- `npm test` — full Vitest suite
- `npm run test:coverage` — full suite with coverage
- `npm run lint` — ESLint checks
- `npm run format:check` — Prettier formatting check
- `npm run build` — production build with Rollup

Suggested verification flows:

- For TypeScript logic changes in `src/`: `npm run build:check && npm test`
- For public API, serialization, or crypto-path changes: `npm run build:check && npm test && npm run build`
- For lint-sensitive edits or broad refactors: `npm run lint && npm run format:check && npm run build:check`
- Before handing off a non-trivial change: `npm run lint && npm run format:check && npm run build:check && npm test`

## Testing Conventions

- Add or update tests for behavior changes.
- Prefer colocated spec files under `src/**/*.spec.ts` for unit-level coverage.
- Use the top-level `tests/` directory for broader compatibility scenarios and fixture-based coverage.

## Reference Docs

- See `CONTRIBUTING.md` for contributor workflow and release notes.
- See `package.json` for the authoritative script list.
