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
        #[arg(long)]
        coefficients: Option<Vec<i64>>,
    },
    Reconstruct {
        // List of shares for reconstruct the secret
        #[arg(long, short)]
        shares: Vec<String>,

        /// Optional prime value
        #[arg(long, short)]
        prime: Option<i64>,
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
            let (share_vals, coefficients, modulus) = generate_share(
                &secret,
                shares,
                threshold,
                prime,
                arg_coefficients.map(|v| -> Vec<BigInt> {
                    v.into_iter().map(|x| -> BigInt { x.into() }).collect()
                }),
            );

            if args.verbose {
                println!("coefficients: {:?}", coefficients);
            }

            println!();
            println!("Shamir's Secret Sharing        ");
            println!("───────────────────────────────");
            println!("Prime: {}", num_format(&modulus));
            println!("Threshold: {} of {}", threshold, shares);
            println!("Secret: {}", num_format(&secret));
            println!("───────────────────────────────");
            println!();
            println!("Shares:");
            for (i, val) in share_vals.iter().enumerate() {
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
            let share_points = parse_shares(&shares);

            // Prime check and default set
            let modulus = match prime {
                None => default_prime(),
                Some(x) => x.into(),
            };

            // For each key point:
            // Calculate: Li(0) mod p
            // Lᵢ(x) = ∏(j≠i) [(x - xⱼ) / (xᵢ - xⱼ)]
            let mut l_vec: Vec<(BigInt, BigInt, BigInt)> = Vec::new();

            // L1 + L2 + L3 = 1 mod p
            let mut verify: BigInt = 0.into();

            // Compute q(0) = D mod p
            // q(x) = y₁ × L₁(x) + y₂ × L₂(x) + y₃ × L₃(x)
            let mut sec: BigInt = 0.into();

            for val in &share_points {
                let mut numerator: BigInt = 1_usize.into();
                let mut denominator: BigInt = 1_usize.into();
                for val2 in &share_points {
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

            if args.verbose {
                println!("Input: {:?} {:?}", shares, prime);
                println!("share_points: {:?}", share_points);
                println!("l_vec: {:?}", l_vec);
            }

            println!();
            println!("Shamir's Secret Reconstruction ");
            println!("───────────────────────────────");
            println!("Prime: {}", num_format(&modulus));
            println!("Shares: {} provided", shares.len());
            println!("───────────────────────────────");
            println!();
            println!("Input Shares:");
            for s in &share_points {
                println!("  {}: {}", &s.0, num_format(&s.1));
            }
            println!();
            println!("✓ Reconstructed Secret");
            println!("──────────────────────");
            println!("Secret: {}", num_format(&sec));
            println!("──────────────────────");
        }
    }
}

fn generate_share(
    secret: &BigInt,
    shares: usize,
    threshold: usize,
    prime: Option<BigInt>,
    coefficients: Option<Vec<BigInt>>,
) -> (Vec<BigInt>, Vec<BigInt>, BigInt) {
    // Modulus = prime
    let modulus = match prime {
        None => default_prime(),
        Some(x) => x.into(),
    };

    // random generate coefficients
    let mut coefficient_vals: Vec<BigInt> = Vec::new();

    match coefficients {
        Some(arg_vals) => {
            for value in arg_vals {
                coefficient_vals.push(value);
            }
        }
        None => {
            let mut rng = rand::thread_rng();

            while coefficient_vals.len() < (threshold - 1) {
                let a = rng.gen_bigint_range(&BigInt::ZERO, &modulus.clone().into());
                coefficient_vals.push(a);
            }
        }
    }

    // The polynomial function
    let polynomial_func = |x: i64| -> BigInt {
        let mut ret: BigInt = 0_u64.into();
        for (index, value) in coefficient_vals.iter().enumerate() {
            ret += value * (x.pow((index as u32) + 1));
        }
        posrem(ret + secret, modulus.clone())
    };

    // Calculate shares
    let mut share_vals: Vec<BigInt> = Vec::new();
    while share_vals.len() < shares {
        let index = share_vals.len();
        let val = polynomial_func((index + 1) as i64);
        share_vals.push(val);
    }

    return (share_vals, coefficient_vals, modulus);
}

fn parse_shares(shares: &Vec<String>) -> Vec<(BigInt, BigInt)> {
    let mut share_points: Vec<(BigInt, BigInt)> = Vec::new();
    for val in shares {
        let s: Vec<&str> = val.split(",").collect();
        if s.len() != 2 {
            eprint!("cannot parse share param: {:?}", val);
            std::process::exit(1);
        }

        let x: BigInt = BigInt::from_str(s[0]).unwrap_or_else(|e| {
            eprint!(
                "cannot parse x={} of share={:?} . Error: {:?}",
                s[0], val, e
            );
            std::process::exit(1);
        });

        let y: BigInt = BigInt::from_str(s[1]).unwrap_or_else(|e| {
            eprint!(
                "cannot parse y={} of share={:?} . Error: {:?}",
                s[1], val, e
            );
            std::process::exit(1);
        });

        share_points.push((x, y));
    }

    return share_points;
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
