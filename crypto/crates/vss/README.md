# Pedersen Verifiable Secret Sharing

The simple CLI application that implements Pedersen Verifiable Secret Sharing protocol.

## Usage

```
vss deal --secret 25 --players 5 --threshold 3

vss verify \
--commitments 0x6f6255bfff57e4db2b6d53449f39908d9b58c062cc56843a18693b94edd8254 \
--commitments 0x330291f819f1f9c5c6c6d0911df16ad4eb6042858979bab91b93a715f74b5b82 \
--commitments 0x1dc6de5a3d6b0cf2216a503cd5c9cf1abb716c8a9a43efd7f5023d67bd182d8e \
--share 3:0x29fef0ed0d9f911c6ebeb13b496d437090ef95dd8dd6a2b9e8716ab58a73474:0x775f4c0c39c270733d68979c6eadadd41b6b0ef2f797ce5bd9559641544f110

vss reconstruct \
--shares 1:0x2cba8feb8a0ac0c1fec1db6a49929c42d238651018fbe1dc2b77eee8e6b1941 \
--shares 4:0xfa88c2030729a0b4dff9aba1ffb54e5ccb5dff85192f4f20fb19293f16e0a6c \
--shares 2:0x3aba358fe3ea9bcb79016bd3620c5d6857dd97049d98c2c4ce4867d014d800a
```

## Cryptographic

Paper: https://cgi.di.uoa.gr/~aggelos/crypto/page8/assets/Pedersen-VSS.PDF

Applying Eliptic Curve addictive group instead of pure finite integer Multiplicative group for better performance and security.

Using Ed25516 with Ristretto255 Prime-Order Group Abstraction to cover the cofactor-8 security. ([ See more ](https://ristretto.group/))

All of operation we just need to perform over Scalar and Ristretto points, hence we don't need to explicitly perform modular.

```
G = Ristretto255 Base Point
H = hash_to_point(sha512("VSS_pedersen_h_generator_v1"))
Commitment = G * scalar(Secret) + H * (scalar(Random_T))
```

Modulus implicity operations will be perform over P = 2^255 + 19 and Q ~ 2^252
