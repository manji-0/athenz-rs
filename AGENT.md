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
