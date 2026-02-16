# Agent Instructions

## Commit messages (AngularJS style)

To keep auto-generated release notes readable, all commits MUST follow the
AngularJS commit message convention.

Required format:

  type(scope): subject

Rules:
- type is one of: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert
- scope is required; use a short area name (for example: core, policy, cli, docs)
- subject is imperative, lower-case, no trailing period, <= 72 chars
- body is optional, separated by a blank line, wrapped at 72 chars
- breaking change: use ! after type/scope and add a footer:
  BREAKING CHANGE: <what changed>

Examples:
- feat(cli): add policy validation command
- fix(core): handle empty tenant list
- chore(ci): pin rust toolchain
- refactor(docs)!: move setup into README
  BREAKING CHANGE: documentation paths updated

## Issue implementation guide

- Keep your primary checkout (the working copy in this repo directory) on the
  `main` branch.
- Before starting work on an issue, update `main` in the primary checkout:
  `git fetch origin && git switch main && git pull --ff-only`.
- For each issue, create a separate worktree based on the up-to-date `main`
  and do all changes there, for example:
  `git worktree add ../ISSUE-123 -b codex/ISSUE-123-update-docs origin/main`.

## Prek checks (mandatory)

- Run Prek checks before pushing or opening a PR:
  `prek run --all-files`

## Build, test, and lint

- Build: `cargo build`
- Test: `cargo nextest run --all-features`
- Doc tests: `cargo test --doc --all-features`
- Format: `cargo fmt`
- Lint: `cargo clippy --all-features`
- Example test target: `cargo nextest run --all-features`

## Examples

- Run a sample example: `cargo run --example issue_access_token`
- Example environment variables are documented in `docs/examples.md`.

## Documentation updates

- Keep `README.md` short and link to `docs/` for details.
- Each new doc should include at least one minimal example.
