# Crypto

## Build Commands

```bash
cargo build           # Build the project
cargo run             # Run the CLI
cargo test            # Run all tests
cargo test <name>     # Run a specific test
cargo clippy          # Run linter
cargo fmt             # Format code
```

## CLI Usage

The `shamir` CLI provides Shamir's Secret Sharing operations:

```bash
# Generate shares from a secret
cargo run -- generate --secret 1234 --shares 5 --threshold 3

# Reconstruct secret from shares
cargo run -- reconstruct --shares "1:abc123" --shares "3:def456" --shares "5:789abc"

# Enable verbose output
cargo run -- --verbose generate --secret 1234 --shares 5 --threshold 3
```

## Architecture

This is a Rust CLI application implementing Shamir's Secret Sharing scheme for threshold cryptography. The project uses:

- **clap**: CLI argument parsing with derive macros
- **num-bigint**: Arbitrary precision arithmetic for cryptographic operations over large finite fields

The default prime is the Curve25519 prime (2^255 - 19), defined in `default_prime()`.

### Current State

The CLI interface is scaffolded with `Generate` and `Reconstruct` commands. The cryptographic operations (polynomial generation, share creation, Lagrange interpolation) are not yet implemented - the output is currently hardcoded placeholder text.
