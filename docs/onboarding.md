# Onboarding

This guide is for engineers newly joining `athenz-rs` maintenance.

## Day 0 checklist

1. Install Rust stable and tools:
   - `rustup toolchain install stable`
   - `cargo install cargo-nextest --locked`
2. Clone the repository and open `README.md`.
3. Run all required local checks once.
4. Read the core docs in this order:
   - `docs/getting-started.md`
   - `docs/clients.md`
   - `docs/token-validation.md`
   - `docs/policy.md`
5. Confirm you can run one example end to end.

## Minimal example

```sh
cargo run --example issue_access_token
```

If the example requires environment variables, use `docs/examples.md`.

## Daily developer workflow

1. Sync local `main`.
2. Pick one issue and keep scope narrow.
3. Implement with tests.
4. Run required checks:

```sh
prek run --all-files
```

5. Open a PR and include:
   - problem statement
   - approach
   - tests run
   - regression risk

## Where to look when stuck

- API surface and coverage: `docs/api-coverage.md`
- Client configuration and auth behavior: `docs/clients.md`, `docs/authentication.md`
- Policy behavior and caveats: `docs/policy.md`
- Project conventions: `CONTRIBUTING.md`
