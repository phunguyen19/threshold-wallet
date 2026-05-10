# Threshold Signature Wallet [WIP]

A threshold signature wallet built from scratch in Rust, implementing cryptographic protocols from their original academic papers. The goal is a fully functional multi-party threshold wallet where no single party ever holds a complete private key.

## Status

| Phase | Protocol                                 | Status      |
| ----- | ---------------------------------------- | ----------- |
| 1     | Shamir Secret Sharing (SSS)              | Done        |
| 2     | Pedersen Verifiable Secret Sharing (VSS) | Done        |
| 3     | Gennaro Distributed Key Generation (DKG) | In Progress |
| 4     | FROST Threshold Signatures               | Planned     |
| 5     | Multi-chain Wallet Integration           | Planned     |
| 6     | Blockchain Integration & Polish          | Planned     |

## Architecture

```
threshold-wallet/
  crypto/                    # Rust workspace for cryptographic primitives
    crates/
      sss/                   # Shamir Secret Sharing
      vss/                   # Pedersen Verifiable Secret Sharing
      dkg/                   # Gennaro Distributed Key Generation
  client/                    # TypeScript CLI client (planned)
  node/                      # Distributed node (planned)
```

Each crate is a standalone CLI tool that can be used independently, and also exposes a library for composition into higher-level protocols.

## Cryptographic Foundations

### Curve & Group

All elliptic curve operations use **Ed25519 with Ristretto255** prime-order group abstraction, which eliminates the cofactor-8 problem inherent in raw Ed25519. This provides ~128-bit security with clean group arithmetic.

- **Scalar field**: order q = 2^252 + 27742317777372353535851937790883648493
- **Base field**: p = 2^255 - 19

### Phase 1: Shamir Secret Sharing

**Paper**: [How to Share a Secret (Shamir, 1979)](https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf)

Implements (k, n) threshold secret sharing using polynomial evaluation over a finite field, with Lagrange interpolation for reconstruction. Any k shares can reconstruct the secret; k-1 shares reveal zero information (information-theoretic security).

**Key details**:

- Default prime: Curve25519 (2^255 - 19)
- Modular arithmetic for information-theoretic security
- Full test coverage including subset reconstruction verification

### Phase 2: Pedersen VSS

**Paper**: [Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing (Pedersen, 1991)](https://cgi.di.uoa.gr/~aggelos/crypto/page8/assets/Pedersen-VSS.PDF)

Extends SSS with commitments that let share recipients verify correctness without revealing the secret. Uses a dual-polynomial approach with blinding factors.

**Key details**:

- Commitment scheme: `E_j = a_j * G + b_j * H`
- H generated via hash-to-point (`SHA-512("VSS_pedersen_h_generator_v1")`) as a nothing-up-my-sleeve construction
- Verification: share holder checks `s_i * G + t_i * H == sum(E_j * i^j)`
- Includes Lagrange reconstruction over Ristretto255 scalars

### Phase 3: Gennaro DKG (In Progress)

Implements distributed key generation where participants jointly generate a shared key without any single party knowing the full secret. Builds on the VSS layer with Feldman commitments for additional verification.

**Completed**:

- Share generation with Pedersen commitments per participant
- Feldman commitment generation and verification
- Pedersen share verification across participants
- Key share derivation (`x_i = sum(s_ji)`)
- CLI tooling: `generate-shares`, `verify-pedersen`, `verify-feldman`, `derive-key-share`

**In progress**:

- Complaint/dispute resolution protocol
- Public key computation
- Adversarial edge case testing

## Usage

Each crate has its own CLI. See individual READMEs for detailed usage:

- [Shamir Secret Sharing (SSS)](./crypto/crates/sss/README.md)
- [Pedersen Verifiable Secret Sharing (VSS)](./crypto/crates/vss/README.md)

### Quick Start

```bash
cd crypto

# Build all crates
cargo build

# Run all tests
cargo test

# SSS: Generate shares and reconstruct
cargo run -p sss -- generate --secret 1234 --shares 5 --threshold 3
cargo run -p sss -- reconstruct -s "1:1494" -s "3:965" -s "5:1188" -p 1613

# VSS: Deal, verify, and reconstruct
cargo run -p vss -- deal --secret 25 --players 5 --threshold 3

# DKG: Generate shares for a participant
cargo run -p dkg -- generate-shares --participant-id 1 --participants 3 --threshold 2
```

## Design Principles

- **Paper-first**: Every protocol is implemented from the original academic paper, not from existing libraries
- **Hand-coded**: All cryptographic logic is written from scratch as a learning exercise -- no copy-paste from reference implementations
- **Test-driven**: Each phase includes unit tests, integration tests, and mathematical verification against known test vectors
- **CLI-composable**: Each protocol phase is usable as a standalone CLI tool and as a library dependency for higher phases

## References

- Shamir, A. (1979). "How to Share a Secret." Communications of the ACM.
- Pedersen, T.P. (1991). "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing."
- Gennaro, R., Jarecki, S., Krawczyk, H., Rabin, T. (1999). "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems."
- Komlo, C., Goldberg, I. (2020). "FROST: Flexible Round-Optimized Schnorr Threshold Signatures."
- [Ristretto Group](https://ristretto.group/) -- prime-order group abstraction for Ed25519

## License

MIT

