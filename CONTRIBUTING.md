# Contributing

Thanks for helping improve `athenz-rs`.

## Development setup

- Rust toolchain (stable)
- Optional: `rustfmt`, `clippy`
- Recommended: `cargo-nextest` (`cargo install cargo-nextest --locked`)

## Build and test

```sh
cargo build
cargo nextest run --all-features
cargo test --doc --all-features
```

## Formatting and linting

```sh
cargo fmt
cargo clippy --all-features
```

## Documentation updates

- Keep `README.md` short and link to `docs/` for details.
- Each new doc should include at least one minimal example.

## Example test invocation

```sh
cargo nextest run --all-features
```
