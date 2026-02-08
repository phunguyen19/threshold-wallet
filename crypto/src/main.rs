use std::str::FromStr;

use clap::{Parser, Subcommand, ValueEnum};
use num_bigint::{BigInt, RandBigInt, Sign};

/// Curve25519 prime: 2^255 - 19 (little-endian bytes)
pub fn default_prime() -> BigInt {
    BigInt::from_bytes_le(
        Sign::Plus,
        &[
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    )
}

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
        #[arg(long, value_parser = clap::value_parser!(BigInt))]
        prime: Option<BigInt>,

        /// Optional coefficients
        #[arg(long, value_delimiter = ',', value_parser = BigInt::from_str)]
        coefficients: Option<Vec<BigInt>>,
    },
    Reconstruct {
        // List of shares for reconstruct the secret
        #[arg(long, short, value_parser = parse_shares_param)]
        shares: Vec<(BigInt, BigInt)>,

        /// Optional prime value
        #[arg(long, short, value_parser = clap::value_parser!(BigInt))]
        prime: Option<BigInt>,
    },
}

fn main() {
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
            let result = generate_share(GenerateShareParams {
                secret: secret.clone(),
                shares,
                threshold,
                prime,
                coefficients: arg_coefficients.map(|v| -> Vec<BigInt> {
                    v.into_iter().map(|x| -> BigInt { x.into() }).collect()
                }),
            });

            if args.verbose {
                println!("coefficients: {:?}", result.coefficients);
            }

            println!();
            println!("Shamir's Secret Sharing        ");
            println!("───────────────────────────────");
            println!("Prime: {}", num_format(&result.modulus));
            println!("Threshold: {} of {}", threshold, &shares);
            println!("Secret: {}", num_format(&secret));
            println!("───────────────────────────────");
            println!();
            println!("Shares:");
            for (i, val) in result.shares.iter().enumerate() {
                println!("  {}: {}", i + 1, num_format(val));
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
            });

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
    }
}

struct GenerateShareParams {
    secret: BigInt,
    shares: usize,
    threshold: usize,
    prime: Option<BigInt>,
    coefficients: Option<Vec<BigInt>>,
}

struct GenerateSharesResult {
    shares: Vec<BigInt>,
    coefficients: Vec<BigInt>,
    modulus: BigInt,
}

fn generate_share(params: GenerateShareParams) -> GenerateSharesResult {
    // Modulus = prime
    let modulus = params.prime.unwrap_or(default_prime());

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
                let a = rng.gen_bigint_range(&BigInt::ZERO, &modulus.clone().into());
                coefficients.push(a);
            }
        }
    }

    // The polynomial function
    let polynomial_func = |x: i64| -> BigInt {
        let mut ret: BigInt = 0_u64.into();
        for (index, value) in coefficients.iter().enumerate() {
            ret += value * (x.pow((index as u32) + 1));
        }
        posrem(ret + &params.secret, modulus.clone())
    };

    // Calculate shares
    let mut shares: Vec<BigInt> = Vec::new();
    while shares.len() < params.shares {
        let index = shares.len();
        let val = polynomial_func((index + 1) as i64);
        shares.push(val);
    }

    return GenerateSharesResult {
        shares,
        coefficients,
        modulus,
    };
}

struct ReconstructParams {
    shares: Vec<(BigInt, BigInt)>,
    prime: Option<BigInt>,
}

//     return (modulus, l_vec, sec);
struct ReconstructResult {
    secret: BigInt,
    prime: BigInt,
    basis_l_vals: Vec<BigInt>,
}

fn reconstruct(params: ReconstructParams) -> ReconstructResult {
    let modulus = params.prime.unwrap_or(default_prime());

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

        let demoninator_inv_mod = denominator.modinv(&modulus).unwrap_or_else(|| {
            println!("cannot calculate inverse mod for share={:?}", val);
            std::process::exit(1);
        });

        let l = posrem(numerator * demoninator_inv_mod, modulus.clone());
        verify += &l;
        sec = (sec + (&val.1 * &l)) % &modulus;
        l_vec.push((val.0.clone(), val.1.clone(), l));
    }

    // Verify: Sum(Li) = 1 mod p
    if verify % &modulus != 1.into() {
        println!("shares are not in the same polynomial");
        std::process::exit(1);
    }

    return ReconstructResult {
        secret: sec,
        prime: modulus,
        basis_l_vals: l_vec.iter().map(|x| x.2.clone()).collect(),
    };
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
        &b - ((-a) % &b)
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
    fn test_simple() {
        assert_eq!(1 + 1, 2);
    }

    #[test]
    fn test_full_flow_default_params() {}

    // TODO: test generate -> reconstruct with default params

    // TODO: test generate with default params
    // TODO: test generate with params full preset
    // TODO: test generate with coefficients preset
    // TODO: test generate with pirme preset
    // TODO: test generate invalid of each params

    // TODO: test reconstruct with default prime
    // TODO: test reconstruct with preset params
    // TODO: test reconstuct with invalid of each params
}
