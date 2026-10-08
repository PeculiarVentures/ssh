# Project Guidelines

## Scope

These instructions apply to the entire repository.

## Project Context

- This project is a TypeScript library for SSH keys and certificates that targets both Node.js and browser environments.
- Keep public APIs portable. Avoid introducing Node-only behavior into source files unless the existing module already depends on it.
- Prefer focused, minimal changes that match the existing layout in `src/`, with unit tests placed next to the updated module when possible.

## Environment

- Use Node.js 22.18 or newer for development (required by tsdown and Vitest). The published package still supports Node.js 20 (`"node": ">=20.0.0"` in `package.json`).
- Use npm scripts from `package.json` for validation instead of ad hoc commands when an equivalent script already exists.

## Release Flow

- Release in two steps: run the **Version Bump** workflow (`patch`/`minor`/`major`) to open a PR that bumps `package.json` and prepends `CHANGELOG.md` via `conventional-changelog -p angular`; merging it triggers **Publish**, which runs checks, publishes to npm, pushes `v<version>` and the moving major tag, and creates the GitHub Release from the matching `CHANGELOG.md` section.
- Publish runs only when no GitHub Release exists for `v<version>` yet, so a failed run can be re-run safely.
- Use Conventional Commit messages (and squash-merge PR titles) so they land in the changelog. Do not hand-edit released `CHANGELOG.md` sections.

## Commit Messages

- Write commit messages in English.
- Follow the Conventional Commits format already documented in `CONTRIBUTING.md` and used in recent history.
- Preferred format: `type(scope): short imperative summary`
- Scope is optional when it does not add value, but use it when the change is localized.
- Release commits are created by the Version Bump workflow as `chore(release): v<version>`.

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

- `npm run typecheck` — TypeScript type check without emitting files
- `npm test` — full Vitest suite
- `npm run test:coverage` — full suite with coverage
- `npm run lint` — oxlint checks
- `npm run format:check` — oxfmt formatting check
- `npm run build` — production build with tsdown

Suggested verification flows:

- For TypeScript logic changes in `src/`: `npm run typecheck && npm test`
- For public API, serialization, or crypto-path changes: `npm run typecheck && npm test && npm run build`
- For lint-sensitive edits or broad refactors: `npm run lint && npm run format:check && npm run typecheck`
- Before handing off a non-trivial change: `npm run lint && npm run format:check && npm run typecheck && npm test`

## Testing Conventions

- Add or update tests for behavior changes.
- Prefer colocated spec files under `src/**/*.spec.ts` for unit-level coverage.
- Use the top-level `tests/` directory for broader compatibility scenarios and fixture-based coverage.

## Reference Docs

- See `CONTRIBUTING.md` for contributor workflow and release notes.
- See `package.json` for the authoritative script list.
