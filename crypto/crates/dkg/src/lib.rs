use std::collections::HashMap;

use curve25519_dalek::{
    RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_POINT, traits::Identity,
};
use num_bigint::BigUint;
use utils::biguint_to_ristretto_point;
use utils::biguint_to_scalar;
use utils::ristretto_point_to_biguint;
use utils::scalar_to_biguint;

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

pub fn feldman_derived_public_key(
    commitments: HashMap<String, Vec<BigUint>>,
) -> Result<BigUint, String> {
    let mut a_i0_vec: Vec<BigUint> = vec![];
    for (p_id, v) in commitments.iter() {
        a_i0_vec.push(
            v.get(0)
                .ok_or(format!("participant {} has no commitments", p_id))?
                .clone(),
        );
    }
    return Ok(scalar_to_biguint(
        &a_i0_vec
            .iter()
            .map(|v| biguint_to_scalar(v))
            .fold(Scalar::ZERO, |sum, a| sum + a),
    ));
}

pub fn gennaro_derive_key_share(shares: Vec<BigUint>) -> Result<BigUint, String> {
    return Ok(scalar_to_biguint(
        &shares
            .iter()
            .map(|v| biguint_to_scalar(&v))
            .fold(Scalar::ZERO, |sum, share| sum + share),
    ));
}
