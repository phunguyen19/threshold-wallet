use std::str::FromStr;

use clap::{Parser, Subcommand, ValueEnum};
use num_bigint::{BigUint, RandBigInt};

// Curve25519 prime: 2^255 - 19
const PRIME_25519_STR: &str =
    "57896044618658097711785492504343953926634992332820282019728792003956564819949";

#[derive(Parser, Debug)]
#[command(name="shamir", version, about, long_about = None)]
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
    Generate {
        /// The secret need to be generated shares
        #[arg(long, value_parser = BigUint::from_str)]
        secret: BigUint,

        /// How many shares
        #[arg(long)]
        shares: usize,

        /// Minimal number of shares need to gather to reconstruct the secret
        #[arg(long)]
        threshold: usize,

        /// Optional prime value
        #[arg(long, value_parser = BigUint::from_str, default_value = PRIME_25519_STR)]
        prime: BigUint,

        /// Optional coefficients
        #[arg(long, value_delimiter = ',', value_parser = BigUint::from_str)]
        coefficients: Option<Vec<BigUint>>,
    },
    Reconstruct {
        // List of shares for reconstruct the secret
        #[arg(long, short, value_parser = parse_shares_param)]
        shares: Vec<(BigUint, BigUint)>,

        /// Optional prime value
        #[arg(long, short, value_parser = BigUint::from_str, default_value = PRIME_25519_STR)]
        prime: BigUint,
    },
}

struct GenerateShareParams {
    secret: BigUint,
    shares: usize,
    threshold: usize,
    prime: BigUint,
    coefficients: Option<Vec<BigUint>>,
}

struct GenerateSharesResult {
    shares: Vec<(BigUint, BigUint)>,
    coefficients: Vec<BigUint>,
    prime: BigUint,
}

struct ReconstructParams {
    shares: Vec<(BigUint, BigUint)>,
    prime: BigUint,
}

struct ReconstructResult {
    secret: BigUint,
    prime: BigUint,
    basis_l_vals: Vec<BigUint>,
}

fn generate_shares(params: GenerateShareParams) -> Result<GenerateSharesResult, String> {
    if params.prime < params.shares.into() {
        return Err("shares count must be <= prime".into());
    }
    if params.secret >= params.prime {
        return Err("invalid secret or prime values. It must be 0 <= secret < prime".into());
    }
    if params.threshold < 2 || params.threshold > params.shares {
        return Err("invalid threshold or share value. It must be 1 < threshold <= shares".into());
    }
    if let Some(c) = &params.coefficients {
        if c.len() != params.threshold - 1 {
            return Err("coefficients list must be equal threshold -1".into());
        }
        if c.iter().any(|x| x >= &params.prime) {
            return Err("coefficient values must be in [0, p)".into());
        }
        if c[c.len() - 1] == BigUint::ZERO {
            return Err("the coefficient a_{k-1} must be > 0".into());
        }
    }

    // random generate coefficients
    let mut coefficients: Vec<BigUint> = Vec::new();

    match params.coefficients {
        Some(arg_vals) => coefficients = arg_vals,
        None => {
            let mut rng = rand::thread_rng();

            for _ in 0..(params.threshold - 2) {
                let a = rng.gen_biguint_range(&BigUint::ZERO, &params.prime);
                coefficients.push(a);
            }

            // ensure coefficient a_{k-1} > 0
            let one: BigUint = 1u32.into();
            coefficients.push(rng.gen_biguint_range(&one, &params.prime));
        }
    }

    // The polynomial function
    let polynomial_func = |x: &BigUint| -> BigUint {
        let mut ret: BigUint = 0_u64.into();
        for (i, value) in coefficients.iter().enumerate() {
            let degree = (i as u32) + 1_u32;
            ret += (value * x.pow(degree)) % &params.prime;
        }
        (ret + &params.secret) % &params.prime
    };

    // Calculate shares
    let mut shares: Vec<(BigUint, BigUint)> = Vec::new();
    for i in 0..params.shares {
        let index: BigUint = (i + 1).into();
        let val = polynomial_func(&index);
        shares.push((index, val));
    }

    Ok(GenerateSharesResult {
        shares,
        coefficients,
        prime: params.prime,
    })
}

fn reconstruct(params: ReconstructParams) -> Result<ReconstructResult, String> {
    if params.shares.len() < 2 {
        return Err("there must be more than 1 share".into());
    }

    if params.prime < params.shares.len().into() {
        return Err("shares count must be <= prime".into());
    }

    for (x, _) in &params.shares {
        if *x > params.prime {
            return Err("x value shouldn't greater than prime".into());
        }
    }

    // validation x shouldn't be 0
    for (x, _) in &params.shares {
        if *x == 0u8.into() {
            return Err("x value shouldn't be 0".into());
        }
    }

    // Validation duplication x
    for (i, el_i) in params.shares.iter().enumerate() {
        for (j, el_j) in params.shares.iter().enumerate() {
            if i != j && el_i.0 == el_j.0 {
                return Err(format!(
                    "shares must be unique, found duplicate x-coordinates: {:?}",
                    el_i.0
                ));
            }
        }
    }

    // For each key point:
    // Calculate: Li(0) mod p
    // Lᵢ(x) = ∏(j≠i) [(x - xⱼ) / (xᵢ - xⱼ)]
    let mut l_vec: Vec<BigUint> = Vec::new();

    // Σ Lᵢ = 1 mod p
    let mut verify: BigUint = 0u32.into();

    // Compute q(0) = D mod p
    // q(x) = y₁ × L₁(x) + y₂ × L₂(x) + y₃ × L₃(x)
    let mut sec: BigUint = 0u32.into();

    for val in &params.shares {
        let mut numerator: BigUint = 1_usize.into();
        let mut denominator: BigUint = 1_usize.into();
        for val2 in &params.shares {
            if val2.0 == val.0 {
                continue;
            }

            if val.0 < val2.0 {
                denominator *= &val2.0 - &val.0;
                numerator *= &val2.0 % &params.prime;
            } else {
                denominator *= &val.0 - &val2.0;
                numerator *= &params.prime - &val2.0;
            }
        }

        let denominator_inv_mod = match denominator.modinv(&params.prime) {
            Some(v) => v,
            None => return Err(format!("cannot calculate inverse mod for share={:?}", val)),
        };

        let numerator_mod = numerator % &params.prime;

        let l = (numerator_mod * denominator_inv_mod) % &params.prime;
        verify += &l;
        sec = (sec + (&val.1 * &l)) % &params.prime;
        l_vec.push(l);
    }

    // Verify: Sum(Li) = 1 mod p
    if verify % &params.prime != 1_usize.into() {
        return Err("shares are not in the same polynomial".into());
    }

    Ok(ReconstructResult {
        secret: sec,
        prime: params.prime.clone(),
        basis_l_vals: l_vec,
    })
}

fn parse_shares_param(val: &str) -> Result<(BigUint, BigUint), String> {
    let s: Vec<&str> = val.split(":").collect();
    if s.len() != 2 {
        return Err(format!("cannot parse share param: {:?}", val));
    }

    let x = match BigUint::from_str(s[0]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse x={} of share={:?} . error: {:?}",
                s[0], val, e
            ));
        }
    };

    let y = match BigUint::from_str(s[1]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse y={} of share={:?} . Error: {:?}",
                s[1], val, e
            ));
        }
    };

    Ok((x, y))
}

fn main() -> Result<(), String> {
    let args = Cli::parse();

    match args.command {
        Commands::Generate {
            secret,
            shares,
            threshold,
            prime,
            coefficients: arg_coefficients,
        } => {
            let result = generate_shares(GenerateShareParams {
                secret: secret.clone(),
                shares,
                threshold,
                prime: prime.clone(),
                coefficients: arg_coefficients,
            })?;

            let number_format = &args.number_format;

            if args.verbose {
                println!("coefficients: {:?}", result.coefficients);
            }

            println!();
            println!("Shamir's Secret Sharing        ");
            println!("───────────────────────────────");
            println!("Prime: {}", number_format.format(&result.prime));
            println!("Threshold: {} of {}", threshold, &shares);
            println!("Secret: {}", number_format.format(&secret));
            println!("───────────────────────────────");
            println!();
            println!("Shares:");
            for (share_index, share_val) in result.shares.iter() {
                println!("  {}: {}", share_index, number_format.format(share_val));
            }
            println!();
            println!("───────────────────────────────");
            println!(
                "⚠️  Store shares separately. Any {} can reconstruct the secret.",
                threshold
            );
        }
        Commands::Reconstruct { shares, prime } => {
            // Validate shares format is correct x,y
            let result = reconstruct(ReconstructParams {
                shares: shares.clone(),
                prime: prime.clone(),
            })?;

            let number_format = &args.number_format;

            if args.verbose {
                println!("Input: {:?} {:?}", shares, prime);
                println!("share_points: {:?}", shares);
                println!("l_vec: {:?}", result.basis_l_vals);
            }

            println!();
            println!("Shamir's Secret Reconstruction ");
            println!("───────────────────────────────");
            println!("Prime: {}", number_format.format(&result.prime));
            println!("Shares: {} provided", shares.len());
            println!("───────────────────────────────");
            println!();
            println!("Input Shares:");
            for s in &shares {
                println!("  {}: {}", &s.0, number_format.format(&s.1));
            }
            println!();
            println!("✓ Reconstructed Secret");
            println!("──────────────────────");
            println!("Secret: {}", number_format.format(&result.secret));
            println!("──────────────────────");
        }
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate all k-sized subsets of a slice
    fn subsets<T: Clone>(items: &[T], k: usize) -> Vec<Vec<T>> {
        let mut result = Vec::new();
        let mut current = Vec::with_capacity(k);
        build_subsets(items, k, 0, &mut current, &mut result);
        result
    }

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

    #[test]
    fn test_full_flow_preset() {
        let generate_result = generate_shares(GenerateShareParams {
            secret: 1234u32.into(),
            shares: 5,
            threshold: 3,
            prime: 1613u32.into(),
            coefficients: Some(vec![166u32.into(), 94u32.into()]),
        })
        .unwrap();

        for val in subsets(&generate_result.shares, 3) {
            let reconstruct_result = reconstruct(ReconstructParams {
                shares: val,
                prime: 1613u32.into(),
            })
            .unwrap();
            assert_eq!(reconstruct_result.secret, 1234u32.into());
        }

        assert_eq!(
            generate_result.shares,
            [
                (1u32.into(), 1494u32.into()),
                (2u32.into(), 329u32.into()),
                (3u32.into(), 965u32.into()),
                (4u32.into(), 176u32.into()),
                (5u32.into(), 1188u32.into())
            ]
        );
    }

    #[test]
    fn test_full_flow_prime_25519() {
        let prime = BigUint::from_str(PRIME_25519_STR).unwrap();
        let generate_result = generate_shares(GenerateShareParams {
            secret: 1234u32.into(),
            shares: 5,
            threshold: 3,
            prime: prime.clone(),
            coefficients: Some(vec![166u32.into(), 94u32.into()]),
        })
        .unwrap();

        for val in subsets(&generate_result.shares, 3) {
            let reconstruct_result = reconstruct(ReconstructParams {
                shares: val,
                prime: prime.clone(),
            })
            .unwrap();
            assert_eq!(reconstruct_result.secret, 1234u32.into());
        }
    }

    #[test]
    fn test_shares_should_not_greater_than_prime() {
        let test_cases_gen_shares: Vec<(usize, BigUint)> =
            vec![(4, 3u32.into()), (1614, 1613u32.into())];

        for (shares, prime) in test_cases_gen_shares {
            let generate_result = generate_shares(GenerateShareParams {
                secret: 1234u32.into(),
                shares,
                threshold: shares - 1,
                prime,
                coefficients: Some(vec![166u32.into(), 94u32.into()]),
            });
            assert!(generate_result.is_err());
            assert!(
                generate_result
                    .err()
                    .unwrap()
                    .contains("shares count must be <= prime")
            )
        }

        let shares: Vec<(BigUint, BigUint)> = vec![
            (1usize.into(), 2usize.into()),
            (2usize.into(), 3usize.into()),
            (3usize.into(), 3usize.into()),
            (4usize.into(), 3usize.into()),
        ];
        let reconstruct_result = reconstruct(ReconstructParams {
            shares,
            prime: 3u32.into(),
        });
        assert!(reconstruct_result.is_err());
        assert!(
            reconstruct_result
                .err()
                .unwrap()
                .contains("shares count must be <= prime")
        )
    }

    #[test]
    fn test_shares_duplicate_x_should_fail() {
        let generate_result = generate_shares(GenerateShareParams {
            secret: 1234u32.into(),
            shares: 5,
            threshold: 3,
            prime: 1613u32.into(),
            coefficients: Some(vec![166u32.into(), 94u32.into()]),
        })
        .unwrap();

        for val in subsets(&generate_result.shares, 3).iter_mut() {
            let dup_item = val.last().unwrap().clone();
            val.push(dup_item.clone());
            let reconstruct_result = reconstruct(ReconstructParams {
                shares: val.clone(),
                prime: 1613u32.into(),
            });
            assert!(reconstruct_result.is_err());
            assert!(
                reconstruct_result.err().unwrap().contains(
                    format!(
                        "shares must be unique, found duplicate x-coordinates: {:?}",
                        dup_item.0
                    )
                    .as_str()
                )
            )
        }
    }

    #[test]
    fn test_shares_not_allow_x_zero() {
        let shares: Vec<(BigUint, BigUint)> = vec![
            (1usize.into(), 2usize.into()),
            (0usize.into(), 1usize.into()),
        ];
        let reconstruct_result = reconstruct(ReconstructParams {
            shares,
            prime: 1613u32.into(),
        });
        assert!(reconstruct_result.is_err());
        assert!(
            reconstruct_result
                .err()
                .unwrap()
                .contains("x value shouldn't be 0")
        )
    }

    #[test]
    fn test_shares_less_than_two_error() {
        let test_cases: Vec<Vec<(BigUint, BigUint)>> =
            vec![vec![], vec![(1usize.into(), 2usize.into())]];

        for shares in test_cases {
            let reconstruct_result = reconstruct(ReconstructParams {
                shares,
                prime: 1613u32.into(),
            });
            assert!(reconstruct_result.is_err(), "result should be fail");
            assert!(
                reconstruct_result
                    .err()
                    .unwrap()
                    .contains("there must be more than 1 share")
            )
        }
    }

    #[test]
    fn test_fewer_than_k_should_not_build_secret() {
        let test_cases: Vec<(usize, usize, Option<Vec<BigUint>>)> = vec![
            (5, 3, Some(vec![166u32.into(), 94u32.into()])),
            (5, 4, None),
            (5, 5, None),
        ];
        for t in test_cases {
            let generate_result = generate_shares(GenerateShareParams {
                secret: 1234u32.into(),
                shares: t.0,
                threshold: t.1,
                prime: BigUint::from_str(PRIME_25519_STR).unwrap(),
                coefficients: t.2,
            })
            .unwrap();
            for val in subsets(&generate_result.shares, t.1 - 1) {
                let reconstruct_result = reconstruct(ReconstructParams {
                    shares: val,
                    prime: BigUint::from_str(PRIME_25519_STR).unwrap(),
                })
                .unwrap();
                assert!(reconstruct_result.secret != 1234u32.into());
            }
        }
    }

    #[test]
    fn test_greater_than_k_should_build_secret() {
        let test_cases: Vec<(usize, usize, Option<Vec<BigUint>>)> = vec![
            (5, 2, None),
            (5, 3, Some(vec![166u32.into(), 94u32.into()])),
            (6, 4, None),
            (7, 5, None),
        ];
        for t in test_cases {
            let generate_result = generate_shares(GenerateShareParams {
                secret: 1234u32.into(),
                shares: t.0,
                threshold: t.1,
                prime: 1613u32.into(),
                coefficients: t.2,
            })
            .unwrap();
            for val in subsets(&generate_result.shares, t.1 + 1) {
                let reconstruct_result = reconstruct(ReconstructParams {
                    shares: val.clone(),
                    prime: 1613u32.into(),
                })
                .unwrap();
                assert!(reconstruct_result.secret == 1234u32.into());
            }
        }
    }

    #[test]
    fn test_random_coefficients() {
        let prime = BigUint::from_str(PRIME_25519_STR).unwrap();
        let test_cases: Vec<usize> = vec![2, 3, 4, 5];
        for t in test_cases {
            let generate_result = generate_shares(GenerateShareParams {
                secret: 1234u32.into(),
                shares: 5,
                threshold: t,
                prime: prime.clone(),
                coefficients: None,
            })
            .unwrap();

            for val in subsets(&generate_result.shares, t) {
                let reconstruct_result = reconstruct(ReconstructParams {
                    shares: val,
                    prime: prime.clone(),
                })
                .unwrap();
                assert_eq!(reconstruct_result.secret, 1234u32.into());
            }
        }
    }

    #[test]
    fn test_generate_secret_value_pass_cases() {
        let test_cases: Vec<(BigUint, BigUint)> = vec![
            (0u32.into(), 1613u32.into()),
            (0u32.into(), BigUint::from_str(PRIME_25519_STR).unwrap()),
            (1u32.into(), 1613u32.into()),
            (1u32.into(), BigUint::from_str(PRIME_25519_STR).unwrap()),
            (1234u32.into(), 1613u32.into()),
            (1234u32.into(), BigUint::from_str(PRIME_25519_STR).unwrap()),
            (1612u32.into(), 1613u32.into()),
        ];
        for (secret, prime) in test_cases {
            let generate_result = generate_shares(GenerateShareParams {
                secret: secret.clone(),
                shares: 2,
                threshold: 2,
                prime: prime.clone(),
                coefficients: None,
            })
            .unwrap();

            for val in subsets(&generate_result.shares, 2) {
                let reconstruct_result = reconstruct(ReconstructParams {
                    shares: val,
                    prime: prime.clone(),
                })
                .unwrap();
                assert_eq!(reconstruct_result.secret, secret);
            }
        }
    }

    #[test]
    fn test_generate_secret_value_fail_cases() {
        let test_cases: Vec<(BigUint, BigUint)> = vec![
            (1613u32.into(), 1613u32.into()),
            (1614u32.into(), 1613u32.into()),
            (
                BigUint::from_str(PRIME_25519_STR).unwrap(),
                BigUint::from_str(PRIME_25519_STR).unwrap(),
            ),
            (
                BigUint::from_str(PRIME_25519_STR).unwrap() + 1u32,
                BigUint::from_str(PRIME_25519_STR).unwrap(),
            ),
        ];
        for test_case in test_cases {
            let t = test_case.clone();
            let generate_result = generate_shares(GenerateShareParams {
                secret: t.0,
                shares: 2,
                threshold: 2,
                prime: t.1,
                coefficients: None,
            });
            assert!(
                generate_result.is_err(),
                "expected test case {:?} to be fail",
                test_case
            );
        }
    }

    #[test]
    fn test_generate_threshold_value() {
        let test_cases: Vec<(bool, usize, usize)> = vec![
            (true, 2, 2),
            (true, 3, 5),
            (true, 5, 5),
            (false, 1, 1),
            (false, 1, 2),
            (false, 0, 1),
            (false, 3, 2),
        ];

        for test_case in test_cases {
            let generate_result = generate_shares(GenerateShareParams {
                secret: 1234u32.into(),
                threshold: test_case.1,
                shares: test_case.2,
                prime: 1613u32.into(),
                coefficients: None,
            });
            match test_case.0 {
                false => {
                    assert!(
                        generate_result.is_err(),
                        "expected test case {:?} to be fail",
                        test_case
                    );
                }
                true => {
                    assert!(
                        generate_result.is_ok(),
                        "expected test case {:?} to be pass",
                        test_case
                    );
                    for val in subsets(&generate_result.unwrap().shares, test_case.1) {
                        let reconstruct_result = reconstruct(ReconstructParams {
                            shares: val,
                            prime: 1613u32.into(),
                        });
                        assert_eq!(reconstruct_result.unwrap().secret, 1234u32.into());
                    }
                }
            }
        }
    }

    #[test]
    fn test_coefficients_user_provided() {
        let test_cases: Vec<(bool, usize, Vec<BigUint>)> = vec![
            // pass cases
            (true, 2, vec![1u32.into()]),
            (true, 3, vec![0u32.into(), 2u32.into()]),
            (true, 3, vec![1u32.into(), 2u32.into()]),
            // fail cases: value must be [0, p)
            (false, 3, vec![1u32.into(), 1613u32.into()]),
            (false, 3, vec![1u32.into(), 1614u32.into()]),
            // fail cases: wrong count
            (false, 2, vec![1u32.into(), 2u32.into()]),
            (false, 3, vec![1u32.into()]),
            (false, 3, vec![1u32.into(), 2u32.into(), 3u32.into()]),
            // fail cases: a_{k-1} = 0
            (false, 2, vec![0u32.into()]),
            (false, 3, vec![1u32.into(), 0u32.into()]),
        ];
        for test_case in test_cases {
            let generate_result = generate_shares(GenerateShareParams {
                secret: 1234u32.into(),
                threshold: test_case.1,
                shares: test_case.1,
                prime: 1613u32.into(),
                coefficients: Some(test_case.2.clone()),
            });
            match test_case.0 {
                false => {
                    assert!(
                        generate_result.is_err(),
                        "expected test case {:?} to be fail",
                        test_case
                    );
                }
                true => {
                    assert!(
                        generate_result.is_ok(),
                        "expected test case {:?} to be pass",
                        test_case
                    );
                    for val in subsets(&generate_result.unwrap().shares, test_case.1) {
                        let reconstruct_result = reconstruct(ReconstructParams {
                            shares: val,
                            prime: 1613u32.into(),
                        });
                        assert_eq!(reconstruct_result.unwrap().secret, 1234u32.into());
                    }
                }
            }
        }
    }
}
