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

## Knowledge Base

### The Paper

This CLI is build based on the paper "How to Share a Secret" by Shamir in 1979.

One of the source file can be found here: https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf

There is an explaination by Wikipedia including its weakness, examples and code snippet: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing

### The Polynomial

This CLI tool apply the Lagrange interpolating polynomial to calculate shares and reconstruct the secret due to it simple and easy to implement for demonstrate the secret sharing algorithm.

The detail of Lagrage interpolation can be found here: https://en.wikipedia.org/wiki/Lagrange_polynomial

### The Default Prime

The default prime value is 2^255 - 19 (Curve25519) which is chosen as it's popular among the cryptographic domain due to balance between security and performance for calculating.

### Why Modulus

We use arithmetic modulus as a best practice to keep the values precise, in range and prevent leakage values information.

### The Test Params

We use the polynomial `q(x) = 1234 + 166x + 94x²  (mod 1613)` for testing.
