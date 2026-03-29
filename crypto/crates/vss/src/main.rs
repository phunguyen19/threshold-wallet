use std::sync::LazyLock;

use clap::{Parser, Subcommand, ValueEnum};
use curve25519_dalek::{
    RistrettoPoint, Scalar, constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto,
    traits::Identity,
};
use num_bigint::BigUint;
use num_traits::Num;
use sha2::Sha512;

static G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
static H: LazyLock<RistrettoPoint> = LazyLock::new(|| {
    let msg = "VSS_pedersen_h_generator_v1";
    RistrettoPoint::hash_from_bytes::<Sha512>(msg.as_bytes())
});

#[derive(Parser, Debug)]
#[command(name="vss", version, about, long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true, value_enum, default_value_t = NumberFormat::Hex)]
    number_format: NumberFormat,

    #[arg(long, global = true)]
    verbose: bool,
}

#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "lower")]
enum NumberFormat {
    Hex,
    Dec,
}

impl NumberFormat {
    fn format(&self, n: &BigUint) -> String {
        match self {
            Self::Hex => format!("{:#x}", n),
            Self::Dec => format!("{}", n),
        }
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate shares for a secret
    Deal {
        /// Secret
        #[arg(long, value_parser = parse_biguint)]
        secret: BigUint,

        /// How many participants
        #[arg(long)]
        players: usize,

        /// Minimal number of shares needed to reconstruct the secret
        #[arg(long)]
        threshold: usize,
    },
    Verify {
        /// VSS commitment values
        #[arg(long, short, value_delimiter = ':', value_parser = parse_biguint)]
        commitments: Vec<BigUint>,

        /// Share
        #[arg(long, short, value_parser = parse_verify_share_param)]
        share: (usize, BigUint, BigUint),
    },
    Reconstruct {
        /// List of shares for reconstruct the secret
        #[arg(long, short, value_parser = parse_reconstruct_shares_param)]
        shares: Vec<(BigUint, BigUint)>,
    },
}

fn parse_verify_share_param(input: &str) -> Result<(usize, BigUint, BigUint), String> {
    // split by :
    let vals: Vec<&str> = input.split(":").collect();
    if vals.len() != 3 {
        return Err(format!(
            "share value must be in format index:s:t, receive: {:?}",
            input
        ));
    }

    // parse each value and return proper error
    let index = match vals[0].parse::<usize>() {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse index value {}, error: {:?}",
                vals[0], e,
            ));
        }
    };

    let s = match parse_biguint(vals[1]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse s={} of share={:?} error: {:?}",
                vals[1], input, e
            ));
        }
    };

    let t = match parse_biguint(vals[2]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse t={} of share={:?} error: {:?}",
                vals[2], input, e
            ));
        }
    };

    Ok((index, s, t))
}

fn parse_reconstruct_shares_param(val: &str) -> Result<(BigUint, BigUint), String> {
    let s: Vec<&str> = val.split(":").collect();
    if s.len() != 2 {
        return Err(format!("cannot parse share param: {:?}", val));
    }

    let x = match parse_biguint(s[0]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse x={} of share={:?} error: {:?}",
                s[0], val, e
            ));
        }
    };

    let y = match parse_biguint(s[1]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse y={} of share={:?} error: {:?}",
                s[1], val, e
            ));
        }
    };

    Ok((x, y))
}

fn parse_biguint(s: &str) -> Result<BigUint, String> {
    if let Some(x) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        BigUint::from_str_radix(x, 16).map_err(|e| e.to_string())
    } else {
        BigUint::from_str_radix(s, 10).map_err(|e| e.to_string())
    }
}

#[derive(Debug)]
struct DealCurveParams {
    secret: BigUint,
    players: usize,
    threshold: usize,
}

#[derive(Debug)]
struct DealCurveResult {
    // E_i
    commitments: Vec<BigUint>,
    // (i, s_i, t_i)
    shares: Vec<(usize, BigUint, BigUint)>,
}

// Commitment: E_j = g^a_j * h^b_j  (in EC: a_j*G + b_j*H)
fn commit_ec(a: &Scalar, b: &Scalar) -> RistrettoPoint {
    G * a + *H * b
}

fn gen_share_ec(x: &Scalar, coeffs: &[Scalar]) -> Scalar {
    coeffs.iter().rev().fold(Scalar::ZERO, |acc, c| acc * x + c)
}

fn deal_ec(params: DealCurveParams) -> Result<DealCurveResult, String> {
    // validate players is valid
    // validate threshold is valid and smaller than players
    if params.threshold < 2 || params.threshold > params.players {
        return Err(format!(
            "threshold must be greater than 1 and smaller than number of players {}, receive {}",
            &params.players, &params.threshold
        ));
    }

    let k: Scalar = biguint_to_scalar(&params.secret).map_err(|e| {
        format!(
            "cannot convert {:?} to scalar, error: {:?}",
            params.secret, e
        )
    })?;

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
        commitments.push(ristretto_point_to_biguint(&commit_ec(
            &coeffs_a[i],
            &coeffs_b[i],
        )));
    }

    let mut shares: Vec<(usize, BigUint, BigUint)> = vec![];
    for i in 1..=params.players {
        let share_s = scalar_to_biguint(&gen_share_ec(&Scalar::from(i as u64), &coeffs_a));
        let share_t = scalar_to_biguint(&gen_share_ec(&Scalar::from(i as u64), &coeffs_b));
        shares.push((i, share_s, share_t));
    }

    Ok(DealCurveResult {
        commitments,
        shares,
    })
}

#[derive(Debug)]
struct VerifyResult {
    result: bool,
    verify_commitment_value: BigUint,
    verify_share_value: BigUint,
}

#[derive(Debug)]
struct VerifyECParams {
    commitments: Vec<BigUint>,
    share: (usize, BigUint, BigUint),
}

// Verify share EC
// E(s_i, t_i) = g*s + h*t = \sum_{j=0}^{k-1}{E_j*i^j}
fn verify_ec(params: VerifyECParams) -> Result<VerifyResult, String> {
    let si: Scalar = biguint_to_scalar(&params.share.1)?;
    let ti: Scalar = biguint_to_scalar(&params.share.2)?;

    let lhs = G * si + *H * ti;

    // rhs sum(ej * i^j)
    let mut rhs = RistrettoPoint::identity(); // (0,0)
    let i = Scalar::from(params.share.0 as u64);
    let mut ipowj = Scalar::ONE; // start with i^0 = 1
    for ej in &params.commitments {
        let ejscalar = biguint_to_ristretto_point(ej)?;
        rhs += ejscalar * ipowj;
        ipowj *= i;
    }

    Ok(VerifyResult {
        result: lhs == rhs,
        verify_commitment_value: ristretto_point_to_biguint(&lhs),
        verify_share_value: ristretto_point_to_biguint(&rhs),
    })
}

struct ReconstructEcParams {
    shares: Vec<(BigUint, BigUint)>,
}

fn reconstruct_ec(params: ReconstructEcParams) -> Result<BigUint, String> {
    let mut shares: Vec<(Scalar, Scalar)> = vec![];
    for s in params.shares {
        let i = biguint_to_scalar(&s.0)?;
        let v = biguint_to_scalar(&s.1)?;
        shares.push((i, v));
    }

    // for each (xi, yi):
    //   li = product over (xj, _) where xj ≠ xi: (-xj) / (xi - xj)
    //   sum += yi * li
    Ok(scalar_to_biguint(&shares.iter().fold(
        Scalar::ZERO,
        |sum, (xi, yi)| {
            let li = shares
                .iter()
                .filter(|(xj, _)| xj != xi)
                .fold(Scalar::ONE, |prod, (xj, _)| {
                    prod * (-xj) * (xi - xj).invert()
                });

            sum + li * yi
        },
    )))
}

fn main() -> Result<(), String> {
    let args = Cli::parse();
    let fmt = &args.number_format;
    let verbose = args.verbose;

    match args.command {
        Commands::Deal {
            secret,
            players,
            threshold,
        } => {
            if verbose {
                println!("secret:    {}", fmt.format(&secret));
                println!("players:   {}", players);
                println!("threshold: {}", threshold);
                println!("curve:     ristretto255");
            }
            let r = deal_ec(DealCurveParams {
                secret,
                players,
                threshold,
            })?;

            let (commitments, shares) = (r.commitments, r.shares);

            println!();
            println!("✓ Deal Complete");
            println!("────────────────────────────────────────");
            println!("Commitments ({}):", commitments.len());
            for (i, c) in commitments.iter().enumerate() {
                println!("  E[{}] = {}", i, fmt.format(c));
            }
            println!();
            println!("Shares ({}):", shares.len());
            for (i, s, t) in &shares {
                println!("  [{}]  s = {}  t = {}", i, fmt.format(s), fmt.format(t));
            }
            println!("────────────────────────────────────────");

            Ok(())
        }
        Commands::Verify { commitments, share } => {
            if verbose {
                println!("share index: {}", share.0);
                println!("s:           {}", fmt.format(&share.1));
                println!("t:           {}", fmt.format(&share.2));
                println!("commitments ({}):", commitments.len());
                for (i, c) in commitments.iter().enumerate() {
                    println!("  E[{}] = {}", i, fmt.format(c));
                }
            }

            let r = verify_ec(VerifyECParams { commitments, share })?;

            println!();
            if r.result {
                println!("✓ Verification Passed");
            } else {
                println!("✗ Verification Failed");
            }
            println!("────────────────────────────────────────");
            if verbose {
                println!(
                    "  lhs (g·s + h·t):          {}",
                    fmt.format(&r.verify_commitment_value)
                );
                println!(
                    "  rhs (Σ Eⱼ·iʲ):            {}",
                    fmt.format(&r.verify_share_value)
                );
            }
            println!("  Result: {}", if r.result { "VALID" } else { "INVALID" });
            println!("────────────────────────────────────────");

            Ok(())
        }
        Commands::Reconstruct { shares } => {
            if verbose {
                println!("shares ({}):", shares.len());
                for (x, y) in &shares {
                    println!("  x = {}  y = {}", fmt.format(x), fmt.format(y));
                }
            }

            let result = reconstruct_ec(ReconstructEcParams { shares })?;

            println!();
            println!("✓ Reconstructed Secret");
            println!("────────────────────────────────────────");
            println!("  Secret: {}", fmt.format(&result));
            println!("────────────────────────────────────────");

            Ok(())
        }
    }
}

/// WARNING: if n > 252-bit value (l), function will perform n mod l
/// because Ristretto255 works under l ~ 252-bit value
fn biguint_to_scalar(n: &BigUint) -> Result<Scalar, String> {
    let mut b = n.to_bytes_le();
    b.resize(64, 0u8);

    // Defensive conversion to make sure
    // it works regardless the size
    let r: [u8; 64] = b[..64]
        .try_into()
        .map_err(|e| format!("cannot convert value {:?} to be scalar, error: {:?}", n, e))?;

    Ok(Scalar::from_bytes_mod_order_wide(&r))
}

fn scalar_to_biguint(n: &Scalar) -> BigUint {
    BigUint::from_bytes_le(n.as_bytes())
}

fn biguint_to_ristretto_point(n: &BigUint) -> Result<RistrettoPoint, String> {
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

fn ristretto_point_to_biguint(n: &RistrettoPoint) -> BigUint {
    BigUint::from_bytes_le(n.compress().as_bytes())
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
                let deal_result = deal_ec(DealCurveParams {
                    secret: secret.clone(),
                    players: *players,
                    threshold: *threshold,
                })
                .unwrap();

                // Test verify
                for share in &deal_result.shares {
                    let verify_result = verify_ec(VerifyECParams {
                        commitments: deal_result.commitments.clone(),
                        share: share.clone(),
                    })
                    .unwrap();
                    assert!(verify_result.result);
                }

                // Test reconstruct
                for subset in subsets(&deal_result.shares, *threshold) {
                    let reconstruct_result = reconstruct_ec(ReconstructEcParams {
                        shares: subset.iter().map(|s| (s.0.into(), s.1.clone())).collect(),
                    });
                    assert_eq!(reconstruct_result.unwrap(), secret);
                }
            }
        }
    }

    #[test]
    fn test_invalid_value_players_threshold() {
        let test_cases: Vec<(usize, usize)> = vec![(0, 0), (1, 1), (2, 1), (5, 1), (5, 6)];
        for t in test_cases {
            let r = deal_ec(DealCurveParams {
                secret: 25_u32.into(),
                players: t.0,
                threshold: t.1,
            });
            assert!(r.is_err());
        }
    }

    #[test]
    fn test_each_deal_run_produces_different_result() {
        let mut deal_results: Vec<DealCurveResult> = vec![];
        for _ in 0..2 {
            deal_results.push(
                deal_ec(DealCurveParams {
                    secret: 25_u32.into(),
                    players: 5,
                    threshold: 3,
                })
                .unwrap(),
            );
        }
        for i in 0..=2 {
            assert!(deal_results[0].commitments[i] != deal_results[1].commitments[i]);
            assert!(deal_results[0].shares[i].0 == deal_results[1].shares[i].0);
            assert!(deal_results[0].shares[i].1 != deal_results[1].shares[i].1);
            assert!(deal_results[0].shares[i].2 != deal_results[1].shares[i].2);
        }
    }

    #[test]
    fn test_verify_fail() {
        let mut deal_results: Vec<DealCurveResult> = vec![];
        for _ in 0..2 {
            deal_results.push(
                deal_ec(DealCurveParams {
                    secret: 25_u32.into(),
                    players: 5,
                    threshold: 3,
                })
                .unwrap(),
            );
        }
        // Try to mismatch verify commitments shares
        for i in 0..5 {
            let verify_result = verify_ec(VerifyECParams {
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
            let deal_result = deal_ec(DealCurveParams {
                secret: secret.clone(),
                players: 5,
                threshold: 3,
            })
            .unwrap();

            // Test verify
            for share in &deal_result.shares {
                let verify_result = verify_ec(VerifyECParams {
                    commitments: deal_result.commitments.clone(),
                    share: share.clone(),
                })
                .unwrap();
                assert!(verify_result.result);
            }

            // Test reconstruct
            for subset in subsets(&deal_result.shares, 2) {
                let reconstruct_result = reconstruct_ec(ReconstructEcParams {
                    shares: subset.iter().map(|s| (s.0.into(), s.1.clone())).collect(),
                });

                // assert the recovery value is not the original secret
                assert!(reconstruct_result.unwrap() != secret);
            }
        }
    }
}
