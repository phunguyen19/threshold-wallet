# Pedersen Verifiable Secret Sharing

The simple CLI application that implements Pedersen Verifiable Secret Sharing protocol.

## Usage

### Deal

```sh
vss deal --secret 25 --players 5 --threshold 3
```

Output Format

```
✓ Deal Complete
────────────────────────────────────────
Commitments (<threshold>):
  E[0] = <hex>
  E[1] = <hex>
  ...
  E[<threshold-1>] = <hex>


Shares (<players>):
  [1]  s = <hex>  t = <hex>
  [2]  s = <hex>  t = <hex>
  ...
  [n]  s = <hex>  t = <hex>
────────────────────────────────────────
```

Output Example

```
✓ Deal Complete
────────────────────────────────────────
Commitments (3):
  E[0] = 0x2d27fceb6a25ea5238ff3da0beb8863aa7f5f678471f46ff808deed227d808d6
  E[1] = 0x7d3bc3671e526f654dca2f72c8f21b4df83b3deb4cc37304c0de6c0ee35f83fa
  E[2] = 0x68a3bca7a491ec6b13b944fb115db545274973a9b5004f69d634ff1b24c82942

Shares (5):
  [1]  s = 0x3ff0b5ccbf3220dfcbff37e8866da5b7c8a2c141c586e6a9a3355f44eb13594  t = 0xa9cadb0bb69523589cab1bd58ce8e23adf3f30751f17d078cddbfa5b4c9b6da
  [2]  s = 0x394ac8844ea05987d6c4c8dbb37fb88c2c3a5f7bd0398d17d34bde65ffa7c51  t = 0x65d7a63d8066c1cc340e62346b5a7ae9b4c0de17dd9f4ca8a43e8741d57ccaf
  [3]  s = 0xec0e3826ae4aa9f82050b2d98736387e78b678984f91c0b01169af090d1a83d  t = 0x2e36533bd4f04bfb67bd4a670e0d6c9e00f9eb632029f7e702c24ed34d58d94
  [4]  s = 0x583b04b3de311230a8a2f5e20191258c1237d0c2e49be6a75b426de274b117e  t = 0x2e6e206b431c1e637b7d46d7501b757c3ea5856e6b7d233e967510fb42f989
  [5]  s = 0x7dd12e2bde5392316fbb91f522907fb7949da3cfee4b99c8b3227e3dd525fee  t = 0xe3e9529e1e2b238ca3fe0047a0375b184b81c2dd60c2a8f4d953bf9cd95e47b
────────────────────────────────────────
```

### Verify

```sh
vss verify \
--commitments <hex> \
--commitments <hex> \
...
--commitments <hex> \
--share <share-index>:<s-hex>:<t-hex>
```

Example usage

```sh
vss verify \
--commitments 0x6f6255bfff57e4db2b6d53449f39908d9b58c062cc56843a18693b94edd8254 \
--commitments 0x330291f819f1f9c5c6c6d0911df16ad4eb6042858979bab91b93a715f74b5b82 \
--commitments 0x1dc6de5a3d6b0cf2216a503cd5c9cf1abb716c8a9a43efd7f5023d67bd182d8e \
--share 3:0x29fef0ed0d9f911c6ebeb13b496d437090ef95dd8dd6a2b9e8716ab58a73474:0x775f4c0c39c270733d68979c6eadadd41b6b0ef2f797ce5bd9559641544f110
```

Example Result

```
✓ Verification Passed
────────────────────────────────────────
  Result: VALID
────────────────────────────────────────
```

### Reconstruct

```sh
vss reconstruct \
--shares <share-index>:<s-hex> \
--shares <share-index>:<s-hex> \
...
--shares <share-index>:<s-hex> \
```

Example usage

```sh
vss reconstruct \
--shares 1:0x2cba8feb8a0ac0c1fec1db6a49929c42d238651018fbe1dc2b77eee8e6b1941 \
--shares 4:0xfa88c2030729a0b4dff9aba1ffb54e5ccb5dff85192f4f20fb19293f16e0a6c \
--shares 2:0x3aba358fe3ea9bcb79016bd3620c5d6857dd97049d98c2c4ce4867d014d800a
```

Example Output

```
✓ Reconstructed Secret
────────────────────────────────────────
  Secret: 0x19
────────────────────────────────────────
```

## Cryptographic

**Paper**: [Pedersen (1991)](https://cgi.di.uoa.gr/~aggelos/crypto/page8/assets/Pedersen-VSS.PDF)

### Curve & Group

Applying Elliptic Curve additive group instead of pure finite integer multiplicative group for better performance with the same security level because EC groups at 256-bit offer ~128-bit security with much smaller key sizes.

Using Ed25519 with Ristretto255 Prime-Order Group Abstraction to eliminate the cofactor-8 problem. [See more](https://ristretto.group/)

All operations are performed over Scalar and Ristretto points without explicit modular arithmetic.

### Commitment Scheme

G and H generator points are defined as follows:

```
G = Ristretto255 Base Point
```

H is generated using hash_to_point function as nothing-up-my-sleeve construction to ensure the dealer cannot know dlog = log_G(H)

```
H = hash_to_point(sha512("VSS_pedersen_h_generator_v1"))
```

Commitment is calculated as

```
Commitment = G * s + H * t
```

where s and t are Ristretto Scalars corresponding to the Pedersen VSS paper:

- s is the secret (or polynomial coefficient),
- t is the blinding factor (random)

### Arithmetic Parameters

Modular arithmetic is performed implicitly over P = 2^255 - 19 and Q = 2^252 + 27742317777372353535851937790883648493
