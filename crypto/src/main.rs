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
            println!("{} {} {} {:?}", secret, shares, threshold, p)
        }
        Commands::Reconstruct { shares } => {
            println!("{:?}", shares)
        }
    }
}
