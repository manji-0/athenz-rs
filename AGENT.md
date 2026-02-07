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

## Linear issues

- Titles must follow AngularJS style in English: `type(scope): subject`
- Body must be written in English
- Track issue type with labels (for example: `feat`, `bug`, `security`, `fix`, `docs`)
- Keep the type label consistent with the title type; remove conflicting type labels

## Issue implementation guide

- Keep your primary checkout (the working copy in this repo directory) on the
  `main` branch.
- Before starting work on an issue, update `main` in the primary checkout:
  `git fetch origin && git switch main && git pull --ff-only`.
- For each issue, create a separate worktree based on the up-to-date `main`
  and do all changes there, for example:
  `git worktree add ../ISSUE-123 -b codex/ISSUE-123-update-docs origin/main`.

## Branch names

- Head branch names must include the Linear issue ID (for example: `codex/ISSUE-18-update-docs`)
