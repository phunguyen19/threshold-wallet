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
cargo run -- reconstruct --shares "1:123" --shares "3:456" --shares "5:789"

# Enable verbose output
cargo run -- --verbose generate --secret 1234 --shares 5 --threshold 3
```

## Architecture

This is a Rust CLI application implementing Shamir's Secret Sharing scheme for threshold cryptography. The project uses:

- **clap**: CLI argument parsing with derive macros
- **num-bigint**: Arbitrary precision arithmetic for cryptographic operations over large finite fields

The default prime is the Curve25519 prime (2^255 - 19).

## Knowledge Base

### The Paper

This CLI is built based on the paper "How to Share a Secret" by Shamir in 1979.

The source paper can be found here: https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf

There is an explanation by Wikipedia including its weakness, examples and code snippet: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing

### The Polynomial

This CLI tool applies the Lagrange interpolating polynomial to calculate shares and reconstruct the secret due to its simplicity and ease of implementation for demonstrating the secret sharing algorithm.

Basically, we use this formula to find the secret:

```
D = Σ yᵢ × Lᵢ(0) mod p
```

with:

- `p` is the prime value we will perform mod operation to prevent value information leakage.
- xᵢ is the x-coordinate and yᵢ is the value of the i-th share. E.g: the 3rd share value is 1598 then `i = 3, y = 1598`;

We also use this formula to verify if the L values are correct:

```
Σ Lᵢ(0) = 1
```

The detail of Lagrange interpolation can be found here: https://en.wikipedia.org/wiki/Lagrange_polynomial.

### The Default Prime

The default prime value is 2^255 - 19 (Curve25519) which is chosen because it's large enough to serve a real cryptographic field (255-bit) and it will be reused in later implementation for FROST and supporting multiple curves.

### Why Modular Arithmetic

We use modular arithmetic as a best practice to prevent value information leakage. Without modular arithmetic, larger share values hint at large coefficients. The mod operation ensures information-theoretic security and the k-1 shares reveal zero information about the secret.

### Why k-1 shares cannot reconstruct a k-threshold secret

We use this Lagrange formula to recalculate the secret:

```
D = Σ yᵢ × Lᵢ(0) mod p

where the sum is over all k shares
```

If users provide only k-1 shares and are missing the k-th share, the formula cannot produce the correct secret. This is because each Lᵢ(0) value depends on the x-coordinates of all k shares in the set — so the missing share doesn't just remove one term, it changes every term in the formula.

For every possible secret value s in [0, p), there exists a valid k-th share that would make the reconstruction produce s. So there are p possible secrets and no way to know which one is correct.

This is called information-theoretic security — it's not just computationally hard to find the secret, it's mathematically impossible. Every guess is equally valid.

### The Test Params

We use the polynomial `q(x) = 1234 + 166x + 94x²  (mod 1613)` for testing.

We can easily calculate the shares from that. We use basic 5 shares:

```
D₁ = q(1) = 1234 + 166(1) + 94(1)² = 1494 mod 1613 = 1494
D₂ = q(2) = 1234 + 166(2) + 94(2)² = 1942 mod 1613 = 329
D₃ = q(3) = 1234 + 166(3) + 94(3)² = 2578 mod 1613 = 965
D₄ = q(4) = 1234 + 166(4) + 94(4)² = 3402 mod 1613 = 176
D₅ = q(5) = 1234 + 166(5) + 94(5)² = 4414 mod 1613 = 1188
```

We apply Lagrange basic polynomial functions to reconstruct the secret:

```
q(x) = y₁ × L₁(x) + y₃ × L₃(x) + y₅ × L₅(x) (mod 1613)

L₁(0) = [(0 - x₃) / (x₁ - x₃)] × [(0 - x₅) / (x₁ - x₅)]
      = [(0 - 3) / (1 - 3)] × [(0 - 5) / (1 - 5)]
      = (-3/-2) × (-5/-4)
      = 3 × 2⁻¹ × 5 × 4⁻¹
      = 15 × 8⁻¹ ≡ 1010 (mod 1613)

L₃(0) = [(0 - x₁) / (x₃ - x₁)] × [(0 - x₅) / (x₃ - x₅)]
      = [(0 - 1) / (3 - 1)] × [(0 - 5) / (3 - 5)]
      = (-1/2) × (-5/-2)
      = -5 × 4⁻¹ ≡ 402 (mod 1613)

L₅(0) = [(0 - x₁) / (x₅ - x₁)] × [(0 - x₃) / (x₅ - x₃)]
      = [(0 - 1) / (5 - 1)] × [(0 - 3) / (5 - 3)]
      = (-1/4) × (-3/2)
      = 3 × 8⁻¹ ≡ 202 (mod 1613)
```

Verify

```
L₁(0) + L₃(0) + L₅(0) ≡ ? (mod 1613)
1010 + 402 + 202 = 1614
1614 mod 1613 = 1 ✅
```

Reconstruct

```
q(0) ≡ y₁ × L₁(0) + y₃ × L₃(0) + y₅ × L₅(0) (mod 1613)
q(0) ≡ 1494 × 1010 + 965 × 402 + 1188 × 202 (mod 1613)
q(0) = D = 1234
```

> NOTE: the calculations skip the detail of mod operation as it's pure math and well-defined in the libraries we used.
