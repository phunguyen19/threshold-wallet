use clap::{Parser, Subcommand, ValueEnum};
use num_bigint::BigUint;
use num_traits::Num;

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
    let vals: Vec<&str> = input.split(':').collect();
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
    let s: Vec<&str> = val.split(':').collect();
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
            let r = vss::deal(vss::DealParams {
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

            let r = vss::verify(vss::VerifyParams { commitments, share })?;

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

            let result = vss::reconstruct(vss::ReconstructParams { shares });

            println!();
            println!("✓ Reconstructed Secret");
            println!("────────────────────────────────────────");
            println!("  Secret: {}", fmt.format(&result));
            println!("────────────────────────────────────────");

            Ok(())
        }
    }
}
