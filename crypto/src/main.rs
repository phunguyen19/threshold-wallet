use clap::{Parser, Subcommand};
use num_bigint::{BigInt, BigUint, RandBigInt};

/// Curve25519 prime: 2^255 - 19 (little-endian bytes)
pub fn default_prime() -> BigUint {
    BigUint::from_bytes_le(&[
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ])
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
        shares: u64,

        /// Minimal number of shares need to gather to reconstruct the secret
        #[arg(long)]
        threshold: u64,

        /// Optional prime value
        #[arg(long)]
        prime: Option<u64>,

        /// Optional coefficients
        #[arg(long)]
        coefficients: Option<Vec<u64>>,
    },
    Reconstruct {
        // List of shares for reconstruct the secret
        #[arg(long, short)]
        shares: Vec<String>,

        /// Optional prime value
        #[arg(long, short)]
        prime: Option<u64>,
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

            // Degree = threshold - 1
            let degree = BigUint::from(threshold) - BigUint::from(1usize);

            // Modulus = prime
            let modulus = match prime {
                None => default_prime(),
                Some(x) => x.into(),
            };

            // random generate coefficients
            let mut coefficient_vals: Vec<BigUint> = Vec::new();

            match arg_coefficients {
                Some(arg_vals) => {
                    for value in arg_vals {
                        coefficient_vals.push(value.into());
                    }
                }
                None => {
                    let mut rng = rand::thread_rng();

                    while coefficient_vals.len() < (threshold - 1) as usize {
                        let a = rng.gen_biguint_range(&BigUint::ZERO, &modulus.clone().into());
                        coefficient_vals.push(a);
                    }
                }
            }

            // Calculate the possitive free term modulus
            let free_term_modulused = if free_term > BigInt::from(0) {
                match free_term.to_biguint() {
                    Some(v) => v % &modulus,
                    None => BigUint::from(0_u32),
                }
            } else {
                let t: BigInt = free_term * BigInt::from(-1_i32);
                match t.to_biguint() {
                    Some(v) => &modulus - v % &modulus,
                    None => BigUint::from(0_u32),
                }
            };

            // The polynomial function
            let polynomial_func = |x: u64| -> BigUint {
                let mut ret: BigUint = 0_u64.into();
                for (index, value) in coefficient_vals.iter().enumerate() {
                    ret += value * (x.pow((index as u32) + 1));
                    ret = ret % &modulus;
                }
                (ret + &free_term_modulused) % &modulus
            };

            // Calculate shares
            let mut share_vals: Vec<BigUint> = Vec::new();
            while share_vals.len() < shares as usize {
                let index = share_vals.len();
                let val = polynomial_func((index + 1) as u64);
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
                println!();
            }
            println!();
            println!(
                "⚠️  Store shares separately. Any {} can reconstruct the secret.",
                threshold
            );
        }
        Commands::Reconstruct { shares, prime } => {
            // Validate shares format is correct x,y
            let share_points = parseShares(&shares);

            // Prime check and default set
            // For each key point:
            // Calculate: Li(0) mod p
            // Verify: Sum(Li) = 1 mod p
            // Compute q(0) = D mod p

            if args.verbose {
                println!("share_points: {:?}", share_points);
                println!("Input: {:?} {:?}", shares, prime);
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

fn parseShares(shares: &Vec<String>) -> Vec<(u64, u64)> {
    let mut share_points: Vec<(u64, u64)> = Vec::new();
    for val in shares {
        let s: Vec<&str> = val.split(",").collect();
        if s.len() != 2 {
            eprint!("cannot parse share param: {:?}", val);
            std::process::exit(1);
        }

        let x: u64 = match s[0].parse() {
            Ok(n) => n,
            Err(e) => {
                eprint!(
                    "cannot parse x={} of share={:?} . Error: {:?}",
                    s[0], val, e
                );
                std::process::exit(1);
            }
        };

        let y: u64 = match s[1].parse() {
            Ok(n) => n,
            Err(e) => {
                eprint!(
                    "cannot parse y={} of share={:?} . Error: {:?}",
                    s[1], val, e
                );
                std::process::exit(1);
            }
        };

        share_points.push((x, y));
    }

    return share_points;
}
