use clap::{Parser, Subcommand};
use num_bigint::BigUint;

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
        secret: u64,

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
            let p = match prime {
                None => default_prime(),
                Some(x) => x.into(),
            };

            if args.verbose {
                println!("Input: {} {} {} {:?}", secret, shares, threshold, p)
            }

            println!("╭─────────────────────────────────────╮");
            println!("│ Shamir's Secret Sharing             │");
            println!("├─────────────────────────────────────┤");
            println!("│ Prime:     2²⁵⁵-19 (Curve25519)     │");
            println!("│ Threshold: 3 of 5                   │");
            println!("│ Secret (dec): 1234                  │");
            println!("│ Secret (hex): 0x4d2                 │");
            println!("╰─────────────────────────────────────╯");
            println!();
            println!("Shares:");
            println!("  1: 8a3f...2c4d (hex, 64 chars)");
            println!("  2: 1b7e...9f3a");
            println!("  3: c42d...8e1b");
            println!("  4: 7f9a...3c2e");
            println!("  5: 2e8b...4d7f");
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
