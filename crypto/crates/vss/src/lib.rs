use std::sync::LazyLock;

use curve25519_dalek::{
    RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_POINT, traits::Identity,
};
use num_bigint::BigUint;
use sha2::Sha512;
use utils::{
    biguint_to_ristretto_point, biguint_to_scalar, ristretto_point_to_biguint, scalar_to_biguint,
};

pub static G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
pub static H: LazyLock<RistrettoPoint> = LazyLock::new(|| {
    let msg = "VSS_pedersen_h_generator_v1";
    RistrettoPoint::hash_from_bytes::<Sha512>(msg.as_bytes())
});

#[derive(Debug)]
pub struct DealParams {
    pub secret: BigUint,
    pub players: usize,
    pub threshold: usize,
}

#[derive(Debug)]
pub struct DealResult {
    // E_i
    pub commitments: Vec<BigUint>,
    // (i, s_i, t_i)
    pub shares: Vec<(usize, BigUint, BigUint)>,
    // coeffs a
    pub coeffs_a: Vec<BigUint>,
    // coeffs b
    pub coeffs_b: Vec<BigUint>,
}

// Commitment: E_j = g^a_j * h^b_j  (in EC: a_j*G + b_j*H)
fn commit(a: &Scalar, b: &Scalar) -> RistrettoPoint {
    G * a + *H * b
}

fn gen_share(x: &Scalar, coeffs: &[Scalar]) -> Scalar {
    coeffs.iter().rev().fold(Scalar::ZERO, |acc, c| acc * x + c)
}

pub fn deal(params: DealParams) -> Result<DealResult, String> {
    // validate players is valid
    // validate threshold is valid and smaller than players
    if params.threshold < 2 || params.threshold > params.players {
        return Err(format!(
            "threshold must be greater than 1 and smaller than number of players {}, receive {}",
            &params.players, &params.threshold
        ));
    }

    let k: Scalar = biguint_to_scalar(&params.secret);

    let mut csprng = rand::rngs::OsRng;
    let t: Scalar = Scalar::random(&mut csprng);

    let mut coeffs_a: Vec<Scalar> = vec![k];
    let mut coeffs_b: Vec<Scalar> = vec![t];
    for _ in 1_usize..params.threshold {
        coeffs_a.push(Scalar::random(&mut csprng));
        coeffs_b.push(Scalar::random(&mut csprng));
    }

    // Generate commitments
    let mut commitments: Vec<BigUint> = vec![];
    for i in 0..params.threshold {
        commitments.push(ristretto_point_to_biguint(&commit(
            &coeffs_a[i],
            &coeffs_b[i],
        )));
    }

    let mut shares: Vec<(usize, BigUint, BigUint)> = vec![];
    for i in 1..=params.players {
        let share_s = scalar_to_biguint(&gen_share(&Scalar::from(i as u64), &coeffs_a));
        let share_t = scalar_to_biguint(&gen_share(&Scalar::from(i as u64), &coeffs_b));
        shares.push((i, share_s, share_t));
    }

    Ok(DealResult {
        commitments,
        shares,
        coeffs_a: coeffs_a.iter().map(|v| scalar_to_biguint(&v)).collect(),
        coeffs_b: coeffs_b.iter().map(|v| scalar_to_biguint(&v)).collect(),
    })
}

#[derive(Debug)]
pub struct VerifyParams {
    pub commitments: Vec<BigUint>,
    pub share: (usize, BigUint, BigUint),
}

#[derive(Debug)]
pub struct VerifyResult {
    pub result: bool,
    pub verify_commitment_value: BigUint,
    pub verify_share_value: BigUint,
}

// Verify share EC
// E(s_i, t_i) = g*s + h*t = \sum_{j=0}^{k-1}{E_j*i^j}
pub fn verify(params: VerifyParams) -> Result<VerifyResult, String> {
    let si: Scalar = biguint_to_scalar(&params.share.1);
    let ti: Scalar = biguint_to_scalar(&params.share.2);

    let lhs = G * si + *H * ti;

    // rhs sum(ej * i^j)
    let mut rhs = RistrettoPoint::identity(); // (0,0)
    let i = Scalar::from(params.share.0 as u64);
    let mut i_pow_j = Scalar::ONE; // start with i^0 = 1
    for ej in &params.commitments {
        let ej_point = biguint_to_ristretto_point(ej)?;
        rhs += ej_point * i_pow_j;
        i_pow_j *= i;
    }

    Ok(VerifyResult {
        result: lhs == rhs,
        verify_commitment_value: ristretto_point_to_biguint(&lhs),
        verify_share_value: ristretto_point_to_biguint(&rhs),
    })
}

#[derive(Debug)]
pub struct ReconstructParams {
    pub shares: Vec<(BigUint, BigUint)>,
}

pub fn reconstruct(params: ReconstructParams) -> BigUint {
    let mut shares: Vec<(Scalar, Scalar)> = vec![];
    for s in params.shares {
        let i = biguint_to_scalar(&s.0);
        let v = biguint_to_scalar(&s.1);
        shares.push((i, v));
    }

    // for each (xi, yi):
    //   li = product over (xj, _) where xj ≠ xi: (-xj) / (xi - xj)
    //   sum += yi * li
    scalar_to_biguint(&shares.iter().fold(Scalar::ZERO, |sum, (xi, yi)| {
        let li = shares
            .iter()
            .filter(|(xj, _)| xj != xi)
            .fold(Scalar::ONE, |prod, (xj, _)| {
                prod * (-xj) * (xi - xj).invert()
            });

        sum + li * yi
    }))
}

#[cfg(test)]
mod tests {
    use num_bigint::RandBigInt;
    use rand::thread_rng;

    use super::*;

    fn build_subsets<T: Clone>(
        items: &[T],
        k: usize,
        start: usize,
        current: &mut Vec<T>,
        result: &mut Vec<Vec<T>>,
    ) {
        if current.len() == k {
            result.push(current.clone());
            return;
        }
        for i in start..items.len() {
            current.push(items[i].clone());
            build_subsets(items, k, i + 1, current, result);
            current.pop();
        }
    }

    /// Generate all k-sized subsets of a slice
    fn subsets<T: Clone>(items: &[T], k: usize) -> Vec<Vec<T>> {
        let mut result = Vec::new();
        let mut current = Vec::with_capacity(k);
        build_subsets(items, k, 0, &mut current, &mut result);
        result
    }

    fn gen_rand_biguint() -> BigUint {
        let mut rng = thread_rng();
        // RistrettoPoint work under q ~ 2^252
        rng.gen_biguint(252)
    }

    #[test]
    fn test_full_flow() {
        let test_cases: Vec<BigUint> = vec![25_u32.into(), gen_rand_biguint()];
        let players_threshold: Vec<(usize, usize)> = vec![(2, 2), (3, 2), (3, 3), (5, 3), (5, 5)];

        for secret in test_cases {
            for (players, threshold) in &players_threshold {
                // test deal
                let deal_result = deal(DealParams {
                    secret: secret.clone(),
                    players: *players,
                    threshold: *threshold,
                })
                .unwrap();

                // Test verify
                for share in &deal_result.shares {
                    let verify_result = verify(VerifyParams {
                        commitments: deal_result.commitments.clone(),
                        share: share.clone(),
                    })
                    .unwrap();
                    assert!(verify_result.result);
                }

                // Test reconstruct
                for subset in subsets(&deal_result.shares, *threshold) {
                    let reconstruct_result = reconstruct(ReconstructParams {
                        shares: subset.iter().map(|s| (s.0.into(), s.1.clone())).collect(),
                    });
                    assert_eq!(reconstruct_result, secret);
                }
            }
        }
    }

    #[test]
    fn test_deal_invalid_value_players_threshold() {
        let test_cases: Vec<(usize, usize)> = vec![(0, 0), (1, 1), (2, 1), (5, 1), (5, 6)];
        for t in test_cases {
            let r = deal(DealParams {
                secret: 25_u32.into(),
                players: t.0,
                threshold: t.1,
            });
            assert!(r.is_err());
        }
    }

    #[test]
    fn test_deal_each_deal_run_produces_different_result() {
        let mut deal_results: Vec<DealResult> = vec![];
        for _ in 0..2 {
            deal_results.push(
                deal(DealParams {
                    secret: 25_u32.into(),
                    players: 5,
                    threshold: 3,
                })
                .unwrap(),
            );
        }
        for i in 0..=2 {
            assert_ne!(
                deal_results[0].commitments[i],
                deal_results[1].commitments[i]
            );
            assert_eq!(deal_results[0].shares[i].0, deal_results[1].shares[i].0);
            assert_ne!(deal_results[0].shares[i].1, deal_results[1].shares[i].1);
            assert_ne!(deal_results[0].shares[i].2, deal_results[1].shares[i].2);
        }
    }

    #[test]
    fn test_verify_fail() {
        let mut deal_results: Vec<DealResult> = vec![];
        for _ in 0..2 {
            deal_results.push(
                deal(DealParams {
                    secret: 25_u32.into(),
                    players: 5,
                    threshold: 3,
                })
                .unwrap(),
            );
        }
        // Try to mismatch verify commitments shares
        for i in 0..5 {
            let verify_result = verify(VerifyParams {
                commitments: deal_results[0].commitments.clone(),
                share: deal_results[1].shares[i].clone(),
            })
            .unwrap();
            assert!(!verify_result.result);
        }
    }

    #[test]
    fn test_reconstruct_incorrect_with_insufficient_shares() {
        let test_cases: Vec<BigUint> = vec![25_u32.into(), gen_rand_biguint()];

        for secret in test_cases {
            // test deal
            let deal_result = deal(DealParams {
                secret: secret.clone(),
                players: 5,
                threshold: 3,
            })
            .unwrap();

            // Test verify
            for share in &deal_result.shares {
                let verify_result = verify(VerifyParams {
                    commitments: deal_result.commitments.clone(),
                    share: share.clone(),
                })
                .unwrap();
                assert!(verify_result.result);
            }

            // Test reconstruct
            for subset in subsets(&deal_result.shares, 2) {
                let reconstruct_result = reconstruct(ReconstructParams {
                    shares: subset.iter().map(|s| (s.0.into(), s.1.clone())).collect(),
                });

                // assert the recovery value is not the original secret
                assert_ne!(reconstruct_result, secret);
            }
        }
    }
}
