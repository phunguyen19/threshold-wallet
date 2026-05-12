use curve25519_dalek::{
    RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto,
    traits::Identity,
};
use num_bigint::BigUint;
use num_bigint::RandBigInt;
use num_traits::Num;
use rand::thread_rng;

static G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// Generate Feldman VSS Commitments
pub fn feldman_commitments(coeffs: Vec<BigUint>) -> Vec<BigUint> {
    coeffs
        .iter()
        .map(|v| ristretto_point_to_biguint(&(G * &biguint_to_scalar(&v))))
        .collect()
}

/// Verify Feldman VSS
pub fn feldman_verify(
    participant_id: usize,
    commitments: Vec<BigUint>,
    share: BigUint,
) -> Result<(bool, BigUint, BigUint), String> {
    // calculate commitment value
    let mut commitment_value = RistrettoPoint::identity(); // (0,0)
    let j = Scalar::from(participant_id as u64);
    let mut j_pow_k = Scalar::ONE;
    for v in commitments {
        commitment_value += biguint_to_ristretto_point(&v)? * j_pow_k;
        j_pow_k *= j;
    }

    // calculate share value
    let share_value = G * biguint_to_scalar(&share);

    Ok((
        commitment_value == share_value,
        ristretto_point_to_biguint(&commitment_value),
        ristretto_point_to_biguint(&share_value),
    ))
}

pub fn gennaro_derive_key_share(shares: Vec<BigUint>) -> Result<BigUint, String> {
    return Ok(scalar_to_biguint(
        &shares
            .iter()
            .map(|v| biguint_to_scalar(&v))
            .fold(Scalar::ZERO, |sum, share| sum + share),
    ));
}

pub fn feldman_derived_public_key(commitments: Vec<BigUint>) -> Result<BigUint, String> {
    return Ok(scalar_to_biguint(
        &commitments
            .iter()
            .map(|v| biguint_to_scalar(&v))
            .fold(Scalar::ZERO, |sum, a| sum + a),
    ));
}

/// WARNING: if n > 252-bit value (l), function will perform n mod l
/// because Ristretto255 works under l ~ 252-bit value
pub fn biguint_to_scalar(n: &BigUint) -> Scalar {
    let mut b = n.to_bytes_le();
    b.resize(64, 0u8);

    let r: [u8; 64] = b[..64].try_into().expect("always 64 bytes after resize");

    Scalar::from_bytes_mod_order_wide(&r)
}

pub fn scalar_to_biguint(n: &Scalar) -> BigUint {
    BigUint::from_bytes_le(n.as_bytes())
}

pub fn biguint_to_ristretto_point(n: &BigUint) -> Result<RistrettoPoint, String> {
    let bytes = n.to_bytes_le();
    let mut buf = [0u8; 32];
    if bytes.len() > 32 {
        return Err("commitment too large for 32-byte point".into());
    }
    buf[..bytes.len()].copy_from_slice(&bytes);
    CompressedRistretto(buf)
        .decompress()
        .ok_or_else(|| format!("invalid compressed point for value {}", n))
}

pub fn ristretto_point_to_biguint(n: &RistrettoPoint) -> BigUint {
    BigUint::from_bytes_le(n.compress().as_bytes())
}

pub fn gen_rand_biguint() -> BigUint {
    let mut rng = thread_rng();
    // RistrettoPoint work under q ~ 2^252
    rng.gen_biguint(252)
}

pub fn gen_rand_scalar() -> Scalar {
    let mut csprng = rand::rngs::OsRng;
    Scalar::random(&mut csprng)
}

pub fn biguint_to_hex(n: &BigUint) -> String {
    format!("0x{}", n.to_str_radix(16))
}

pub fn hex_to_biguint(s: &str) -> Result<BigUint, String> {
    if let Some(x) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        BigUint::from_str_radix(x, 16).map_err(|e| e.to_string())
    } else {
        BigUint::from_str_radix(s, 10).map_err(|e| e.to_string())
    }
}

pub fn hex_to_scalar(s: &str) -> Result<Scalar, String> {
    Ok(biguint_to_scalar(&hex_to_biguint(&s)?))
}

pub fn hex_to_ristretto_point(s: &str) -> Result<RistrettoPoint, String> {
    Ok(biguint_to_ristretto_point(&hex_to_biguint(&s)?)?)
}

pub fn ristretto_point_to_hex(v: &RistrettoPoint) -> String {
    biguint_to_hex(&ristretto_point_to_biguint(v))
}
