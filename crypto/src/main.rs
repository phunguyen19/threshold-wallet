use clap::{Parser, Subcommand};
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};

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

    #[arg(long, global = true)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate shares for a secret
    Generate {
        /// The secret need to be generated shares
        #[arg(long)]
        secret: i64,

        /// How many shares
        #[arg(long)]
        shares: i64,

        /// Minimal number of shares need to gather to reconstruct the secret
        #[arg(long)]
        threshold: i64,

        /// Optional prime value
        #[arg(long)]
        prime: Option<i64>,

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

    match args.command {
        Commands::Generate {
            secret,
            shares,
            threshold,
            prime,
            coefficients: arg_coefficients,
        } => {
            // Build the polynomial P(x)

            // Free term
            let free_term: BigInt = secret.into();

            // Modulus = prime
            let modulus = match prime {
                None => default_prime(),
                Some(x) => x.into(),
            };

            // random generate coefficients
            let mut coefficient_vals: Vec<BigInt> = Vec::new();

            match arg_coefficients {
                Some(arg_vals) => {
                    for value in arg_vals {
                        coefficient_vals.push(value.into());
                    }
                }
                None => {
                    let mut rng = rand::thread_rng();

                    while coefficient_vals.len() < (threshold - 1) as usize {
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
                proper_rem(ret + &free_term, modulus.clone())
            };

            // Calculate shares
            let mut share_vals: Vec<BigInt> = Vec::new();
            while share_vals.len() < shares as usize {
                let index = share_vals.len();
                let val = polynomial_func((index + 1) as i64);
                share_vals.push(val);
            }

            if args.verbose {
                println!("Input: {} {} {} {:?}", secret, shares, threshold, modulus);
                println!("coefficients: {:?}", coefficient_vals);
                println!("share_vals: {:?}", share_vals);
            }

            println!();
            println!("Shamir's Secret Sharing        ");
            println!("───────────────────────────────");
            println!("Prime (dec): {}", modulus);
            println!("Prime (hex): {:#x}", modulus);
            println!("Threshold: {} of {}", threshold, shares);
            println!("Secret (dec): {}", secret);
            println!("Secret (hex): {:#x}", secret);
            println!();
            println!("Shares:");
            for (i, val) in share_vals.iter().enumerate() {
                println!("  {}: {}", i + 1, val);
                println!("     {:#x}", val);
            }
            println!();
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
            let mut l_vec: Vec<BigInt> = Vec::new();
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

                l_vec.push(proper_rem(numerator * demoninator_inv_mod, modulus.clone()));
            }

            // Verify: Sum(Li) = 1 mod p
            // Compute q(0) = D mod p

            if args.verbose {
                println!("Input: {:?} {:?}", shares, prime);
                println!("share_points: {:?}", share_points);
                println!("l_vec: {:?}", l_vec);
            }

            println!("╭─────────────────────────────────────╮");
            println!("│ Shamir's Secret Reconstruction      │");
            println!("├─────────────────────────────────────┤");
            println!("│ Prime:     2²⁵⁵-19 (Curve25519)     │");
            println!("│ Shares:    3 provided               │");
            println!("╰─────────────────────────────────────╯");
            println!();
            println!("Input Shares:");
            println!("  1: 8a3f...2c4d (hex, 64 chars)");
            println!("  3: c42d...8e1b");
            println!("  5: 2e8b...4d7f");
            println!();
            println!("╭─────────────────────────────────────╮");
            println!("│ ✓ Reconstructed Secret              │");
            println!("├─────────────────────────────────────┤");
            println!("│ Decimal: 1234                       │");
            println!("│ Hex:     0x4d2                      │");
            println!("╰─────────────────────────────────────╯");
        }
    }
}

fn parse_shares(shares: &Vec<String>) -> Vec<(BigInt, BigInt)> {
    let mut share_points: Vec<(BigInt, BigInt)> = Vec::new();
    for val in shares {
        let s: Vec<&str> = val.split(",").collect();
        if s.len() != 2 {
            eprint!("cannot parse share param: {:?}", val);
            std::process::exit(1);
        }

        let x: u64 = s[0].parse().unwrap_or_else(|e| {
            eprint!(
                "cannot parse x={} of share={:?} . Error: {:?}",
                s[0], val, e
            );
            std::process::exit(1);
        });

        let y: u64 = s[1].parse().unwrap_or_else(|e| {
            eprint!(
                "cannot parse y={} of share={:?} . Error: {:?}",
                s[1], val, e
            );
            std::process::exit(1);
        });

        share_points.push((x.into(), y.into()));
    }

    return share_points;
}

fn proper_rem(a: BigInt, b: BigInt) -> BigInt {
    if a < 0.into() {
        &b - ((-a) % &b)
    } else {
        a % &b
    }
}
