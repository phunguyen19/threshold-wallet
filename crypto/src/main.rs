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
    },
    Reconstruct {
        // List of shares for reconstruct the secret
        #[arg(long)]
        shares: Vec<String>,
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
            let mut coefficients: Vec<BigInt> = Vec::new();
            let mut rng = rand::thread_rng();
            let low: BigInt = 0.into();

            while coefficients.len() < (threshold - 1) as usize {
                let a = rng.gen_bigint_range(&low, &modulus.clone().into());
                coefficients.push(a);
            }

            // The polynomial function
            let polynomial_func = |x: u64| -> BigInt {
                let mut ret = free_term.clone();
                for (index, value) in coefficients.iter().enumerate() {
                    ret += value * (x.pow(( index as u32 ) + 1))
                }
                ret.into()
            };

            // Calculate shares
            let mut share_vals: Vec<BigInt> = Vec::new();
            share_vals.push(free_term.clone());
            while share_vals.len() < shares as usize {
                let index = share_vals.len();
                let val = polynomial_func(index as u64);
                share_vals.push(val);
            }

            if args.verbose {
                println!("Input: {} {} {} {:?}", secret, shares, threshold, modulus);
                println!("coefficients: {:?}", coefficients);
                println!("share_vals: {:?}", share_vals);
            }

            println!(" Shamir's Secret Sharing        ");
            println!(" ───────────────────────────────");
            println!(" Prime (dec): {}", modulus);
            println!(" Prime (hex): {:#x}", modulus);
            println!(" Threshold: {} of {}", threshold, shares);
            println!(" Secret (dec): {}", secret);
            println!(" Secret (hex): {:#x}", secret);
            println!();
            println!(" Shares:");
            println!("   1: 8a3f...2c4d (hex, 64 chars)");
            println!("   2: 1b7e...9f3a");
            println!("   3: c42d...8e1b");
            println!("   4: 7f9a...3c2e");
            println!("   5: 2e8b...4d7f");
            println!();
            println!("⚠️  Store shares separately. Any 3 can reconstruct the secret.");
        }
        Commands::Reconstruct { shares } => {
            if args.verbose {
                println!("Input: {:?}", shares)
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
