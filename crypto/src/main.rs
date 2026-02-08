use std::str::FromStr;

use clap::{Parser, Subcommand, ValueEnum};
use num_bigint::{BigInt, RandBigInt};

// Curve25519 prime: 2^255 - 19
const PRIME_25519: &str =
    "57896044618658097711785492504343953926634992332820282019728792003956564819949";

#[derive(Parser, Debug)]
#[command(name="shamir", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true, value_enum, default_value_t = NumMod::Hex)]
    num_mod: NumMod,

    #[arg(long, global = true)]
    verbose: bool,
}

#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "lower")]
enum NumMod {
    Hex,
    Dec,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate shares for a secret
    Generate {
        /// The secret need to be generated shares
        #[arg(long, value_parser = BigInt::from_str)]
        secret: BigInt,

        /// How many shares
        #[arg(long)]
        shares: usize,

        /// Minimal number of shares need to gather to reconstruct the secret
        #[arg(long)]
        threshold: usize,

        /// Optional prime value
        #[arg(long, value_parser = BigInt::from_str, default_value = PRIME_25519)]
        prime: BigInt,

        /// Optional coefficients
        #[arg(long, value_delimiter = ',', value_parser = BigInt::from_str)]
        coefficients: Option<Vec<BigInt>>,
    },
    Reconstruct {
        // List of shares for reconstruct the secret
        #[arg(long, short, value_parser = parse_shares_param)]
        shares: Vec<(BigInt, BigInt)>,

        /// Optional prime value
        #[arg(long, short, value_parser = BigInt::from_str, default_value = PRIME_25519)]
        prime: BigInt,
    },
}

fn main() -> Result<(), String> {
    let args = Cli::parse();
    let num_format = new_num_format(&args.num_mod);

    match args.command {
        Commands::Generate {
            secret,
            shares,
            threshold,
            prime,
            coefficients: arg_coefficients,
        } => {
            let result: GenerateSharesResult;
            match generate_share(GenerateShareParams {
                secret: secret.clone(),
                shares,
                threshold,
                prime: prime.clone(),
                coefficients: arg_coefficients.map(|v| -> Vec<BigInt> {
                    v.into_iter().map(|x| -> BigInt { x.into() }).collect()
                }),
            }) {
                Ok(r) => result = r,
                Err(e) => return Err(e),
            };

            if args.verbose {
                println!("coefficients: {:?}", result.coefficients);
            }

            println!();
            println!("Shamir's Secret Sharing        ");
            println!("───────────────────────────────");
            println!("Prime: {}", num_format(&result.prime));
            println!("Threshold: {} of {}", threshold, &shares);
            println!("Secret: {}", num_format(&secret));
            println!("───────────────────────────────");
            println!();
            println!("Shares:");
            for (_, (share_index, share_val)) in result.shares.iter().enumerate() {
                println!("  {}: {}", share_index, num_format(share_val));
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
            let result: ReconstructResult;
            match reconstruct(ReconstructParams {
                shares: shares.clone(),
                prime: prime.clone(),
            }) {
                Ok(v) => result = v,
                Err(e) => return Err(e),
            };

            if args.verbose {
                println!("Input: {:?} {:?}", shares, prime);
                println!("share_points: {:?}", shares);
                println!("l_vec: {:?}", result.basis_l_vals);
            }

            println!();
            println!("Shamir's Secret Reconstruction ");
            println!("───────────────────────────────");
            println!("Prime: {}", num_format(&result.prime));
            println!("Shares: {} provided", shares.len());
            println!("───────────────────────────────");
            println!();
            println!("Input Shares:");
            for s in &shares {
                println!("  {}: {}", &s.0, num_format(&s.1));
            }
            println!();
            println!("✓ Reconstructed Secret");
            println!("──────────────────────");
            println!("Secret: {}", num_format(&result.secret));
            println!("──────────────────────");
        }
    };

    Ok(())
}

struct GenerateShareParams {
    secret: BigInt,
    shares: usize,
    threshold: usize,
    prime: BigInt,
    coefficients: Option<Vec<BigInt>>,
}

struct GenerateSharesResult {
    shares: Vec<(BigInt, BigInt)>,
    coefficients: Vec<BigInt>,
    prime: BigInt,
}

fn generate_share(params: GenerateShareParams) -> Result<GenerateSharesResult, String> {
    if params.secret >= params.prime {
        return Err("secret must be smaller than prime value".into());
    }
    if params.threshold > params.shares {
        return Err("threshold cannot be greater than number of shares".into());
    }

    // random generate coefficients
    let mut coefficients: Vec<BigInt> = Vec::new();

    match params.coefficients {
        Some(arg_vals) => {
            for value in arg_vals {
                coefficients.push(value);
            }
        }
        None => {
            let mut rng = rand::thread_rng();

            while coefficients.len() < (params.threshold - 1) {
                let a = rng.gen_bigint_range(&BigInt::ZERO, &params.prime.clone().into());
                coefficients.push(a);
            }
        }
    }

    // The polynomial function
    let polynomial_func = |x: BigInt| -> BigInt {
        let mut ret: BigInt = 0_u64.into();
        for (i, value) in coefficients.iter().enumerate() {
            let degree = (i as u32) + 1_u32;
            ret += posrem(value * x.pow(degree), params.prime.clone());
        }
        posrem(ret + &params.secret, params.prime.clone())
    };

    // Calculate shares
    let mut shares: Vec<(BigInt, BigInt)> = Vec::new();
    while shares.len() < params.shares {
        let index = shares.len() + 1;
        let val = polynomial_func(index.into());
        shares.push((index.into(), val));
    }

    return Ok(GenerateSharesResult {
        shares,
        coefficients,
        prime: params.prime,
    });
}

struct ReconstructParams {
    shares: Vec<(BigInt, BigInt)>,
    prime: BigInt,
}

//     return (modulus, l_vec, sec);
struct ReconstructResult {
    secret: BigInt,
    prime: BigInt,
    basis_l_vals: Vec<BigInt>,
}

fn reconstruct(params: ReconstructParams) -> Result<ReconstructResult, String> {
    // For each key point:
    // Calculate: Li(0) mod p
    // Lᵢ(x) = ∏(j≠i) [(x - xⱼ) / (xᵢ - xⱼ)]
    let mut l_vec: Vec<(BigInt, BigInt, BigInt)> = Vec::new();

    // L1 + L2 + L3 = 1 mod p
    let mut verify: BigInt = 0.into();

    // Compute q(0) = D mod p
    // q(x) = y₁ × L₁(x) + y₂ × L₂(x) + y₃ × L₃(x)
    let mut sec: BigInt = 0.into();

    for val in &params.shares {
        let mut numerator: BigInt = 1_usize.into();
        let mut denominator: BigInt = 1_usize.into();
        for val2 in &params.shares {
            if val2.0 == val.0 {
                continue;
            }
            numerator *= -&val2.0;
            denominator *= &val.0 - &val2.0;
        }

        if denominator < 0.into() {
            numerator = -numerator;
            denominator = -denominator;
        }

        let denominator_inv_mod: BigInt;
        match denominator.modinv(&params.prime) {
            Some(v) => denominator_inv_mod = v,
            None => return Err(format!("cannot calculate inverse mod for share={:?}", val)),
        };

        let l = posrem(numerator * denominator_inv_mod, params.prime.clone());
        verify += &l;
        sec = posrem(sec + (&val.1 * &l), params.prime.clone());
        l_vec.push((val.0.clone(), val.1.clone(), l));
    }

    // Verify: Sum(Li) = 1 mod p
    if verify % &params.prime != 1.into() {
        return Err("shares are not in the same polynomial".into());
    }

    return Ok(ReconstructResult {
        secret: sec,
        prime: params.prime,
        basis_l_vals: l_vec.iter().map(|x| x.2.clone()).collect(),
    });
}

fn parse_shares_param(val: &str) -> Result<(BigInt, BigInt), String> {
    let mut share_point: (BigInt, BigInt) = (0.into(), 0.into());
    let s: Vec<&str> = val.split(",").collect();
    if s.len() != 2 {
        return Err(format!("cannot parse share param: {:?}", val));
    }

    match BigInt::from_str(s[0]) {
        Ok(x) => share_point.0 = x,
        Err(e) => {
            return Err(format!(
                "cannot parse x={} of share={:?} . error: {:?}",
                s[0], val, e
            ));
        }
    };

    match BigInt::from_str(s[1]) {
        Ok(y) => share_point.1 = y,
        Err(e) => {
            return Err(format!(
                "cannot parse y={} of share={:?} . Error: {:?}",
                s[1], val, e
            ));
        }
    }

    Ok(share_point)
}

fn posrem(a: BigInt, b: BigInt) -> BigInt {
    if a < 0.into() {
        (&b - ((-a) % &b)) % &b
    } else {
        a % &b
    }
}

fn new_num_format(m: &NumMod) -> Box<dyn Fn(&BigInt) -> String> {
    match m {
        NumMod::Hex => Box::new(move |n: &BigInt| format!("{:#x}", n)),
        NumMod::Dec => Box::new(move |n: &BigInt| format!("{}", n)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_flow_preset() {
        let generate_result = generate_share(GenerateShareParams {
            secret: 1234.into(),
            shares: 5,
            threshold: 3,
            prime: 1613.into(),
            coefficients: Some(vec![166.into(), 94.into()]),
        })
        .unwrap();
        assert_eq!(
            generate_result.shares,
            [
                (1.into(), 1494.into()),
                (2.into(), 329.into()),
                (3.into(), 965.into()),
                (4.into(), 176.into()),
                (5.into(), 1188.into())
            ]
        );
        let reconstruct_result = reconstruct(ReconstructParams {
            shares: vec![
                (1.into(), 1494.into()),
                (3.into(), 965.into()),
                (5.into(), 1188.into()),
            ],
            prime: 1613.into(),
        })
        .unwrap();
        assert_eq!(reconstruct_result.secret, 1234.into());
    }

    #[test]
    fn test_full_flow_prime_25519() {
        let prime = BigInt::from_str(PRIME_25519).unwrap();
        let generate_result = generate_share(GenerateShareParams {
            secret: 1234.into(),
            shares: 5,
            threshold: 3,
            prime: prime.clone(),
            coefficients: Some(vec![166.into(), 94.into()]),
        })
        .unwrap();
        let reconstruct_result = reconstruct(ReconstructParams {
            shares: vec![
                generate_result.shares[0].clone(),
                generate_result.shares[2].clone(),
                generate_result.shares[4].clone(),
            ],
            prime,
        })
        .unwrap();
        assert_eq!(reconstruct_result.secret, 1234.into());
    }

    #[test]
    fn test_random_coefficients() {
        let prime = BigInt::from_str(PRIME_25519).unwrap();
        let generate_result = generate_share(GenerateShareParams {
            secret: 1234.into(),
            shares: 5,
            threshold: 3,
            prime: prime.clone(),
            coefficients: None,
        })
        .unwrap();
        let reconstruct_result = reconstruct(ReconstructParams {
            shares: vec![
                generate_result.shares[0].clone(),
                generate_result.shares[2].clone(),
                generate_result.shares[4].clone(),
            ],
            prime,
        })
        .unwrap();
        assert_eq!(reconstruct_result.secret, 1234.into());
    }

    #[test]
    fn test_generate_secret_must_smaller_than_prime_pass_cases() {
        let pass_cases: Vec<(BigInt, BigInt)> = vec![
            (0.into(), 1613.into()),
            (0.into(), BigInt::from_str(PRIME_25519).unwrap()),
            (1.into(), 1613.into()),
            (1.into(), BigInt::from_str(PRIME_25519).unwrap()),
            (1234.into(), 1613.into()),
            (1234.into(), BigInt::from_str(PRIME_25519).unwrap()),
            (1612.into(), 1613.into()),
            (
                BigInt::from_str(PRIME_25519).unwrap() - 1,
                BigInt::from_str(PRIME_25519).unwrap(),
            ),
        ];
        for (secret, prime) in pass_cases {
            let generate_result = generate_share(GenerateShareParams {
                secret: secret.clone(),
                shares: 2,
                threshold: 2,
                prime: prime.clone(),
                coefficients: None,
            })
            .unwrap();
            let reconstruct_result = reconstruct(ReconstructParams {
                shares: generate_result.shares,
                prime,
            })
            .unwrap();
            assert_eq!(reconstruct_result.secret, secret);
        }
    }

    #[test]
    fn test_generate_secret_must_smaller_than_prime_fail_cases() {
        let fail_cases: Vec<(BigInt, BigInt)> = vec![
            ((-1_isize).into(), 1613.into()),
            ((-1_isize).into(), BigInt::from_str(PRIME_25519).unwrap()),
            (1613.into(), 1613.into()),
            (1614.into(), 1613.into()),
            (
                BigInt::from_str(PRIME_25519).unwrap(),
                BigInt::from_str(PRIME_25519).unwrap(),
            ),
            (
                BigInt::from_str(PRIME_25519).unwrap() + 1,
                BigInt::from_str(PRIME_25519).unwrap(),
            ),
        ];
    }

    #[test]
    fn test_posrem() {
        let test_cases = [
            (-13, 5, 2),
            (-5, 5, 0),
            (-1, 5, 4),
            (0, 5, 0),
            (1, 5, 1),
            (5, 5, 0),
            (13, 5, 3),
        ];

        for (a, b, expected) in test_cases {
            assert_eq!(
                posrem(a.into(), b.into()),
                expected.into(),
                "posrem({}, {}) should be {}",
                a,
                b,
                expected
            )
        }
    }
}
