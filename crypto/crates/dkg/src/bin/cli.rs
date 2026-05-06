use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;

use clap::{Parser, Subcommand, ValueEnum};
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use num_bigint::BigUint;
use num_bigint::RandBigInt;
use num_traits::Num;
use rand::thread_rng;
use serde::Deserialize;
use serde::Serialize;
use vss::DealParams;

#[derive(Parser, Debug)]
#[command(name = "dkg", version, about, long_about = None)]
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
    /// Generate commitments and shares for DKG
    GenerateShares {
        /// Participant ID
        #[arg(long)]
        participant_id: usize,

        /// How many participants
        #[arg(long)]
        participants: usize,

        /// Minimal number
        #[arg(long)]
        threshold: usize,
    },

    /// Generate shares for a secret
    GenerateShares2 {
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
    VerifyShares {
        /// VSS commitment values
        #[arg(long, short, value_delimiter = ':', value_parser = parse_biguint)]
        commitments: Vec<BigUint>,

        /// Share
        #[arg(long, short, value_parser = parse_verify_share_param)]
        share: (usize, BigUint, BigUint),
    },
    /// Derive key share of each play from received shares by other players.
    /// x_i = sum(s_ji)
    DeriveKeyShare {
        #[arg(long, short, value_delimiter = ':', value_parser = parse_biguint)]
        shares: Vec<BigUint>,
    },
    /// Generate Feldman Commitments and broadcast to all players
    /// A_ik = g^a_ik (for k = 0,...t of coeff-th of polynomial f)
    FeldmanCommitments {},
    ///
    VerifyFeldman {},
    ReconstructShare {
        /// List of shares for reconstruct the secret
        #[arg(long, short, value_parser = parse_reconstruct_shares_param)]
        shares: Vec<(BigUint, BigUint)>,
    },
    ComputePublicKey {},
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

#[derive(Debug)]
struct DeriveKeyShareParams {
    shares: Vec<Scalar>,
}

#[derive(Debug)]
struct DeriveKeyShareResult {
    result: Scalar,
}

fn derive_key_share(params: DeriveKeyShareParams) -> DeriveKeyShareResult {
    DeriveKeyShareResult {
        result: params
            .shares
            .iter()
            .fold(Scalar::ZERO, |sum, share| sum + share),
    }
}

struct GenerateShareParams {
    participant_id: usize,
    participants: usize,
    threshold: usize,
}

fn generate_shares(params: GenerateShareParams) -> Result<(), String> {
    let random_secret = gen_rand_biguint();

    let vss_result = vss::deal(DealParams {
        secret: random_secret,
        players: params.participants,
        threshold: params.threshold,
    })?;

    let _ = write_participant_file(Participant {
        id: params.participant_id,
        pedersen_commitments: vss_result
            .commitments
            .iter()
            .map(|v| format!("0x{}", v.to_str_radix(16)))
            .collect(),
    });
    let participant = read_participant_file(params.participant_id);
    println!("{:?}", participant);

    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
struct Participant {
    id: usize,
    pedersen_commitments: Vec<String>,
}

fn write_participant_file(participant: Participant) -> Result<(), Box<dyn Error>> {
    let file = File::create(format!("output/participant-{}.json", participant.id))?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &participant)?;
    Ok(())
}

fn read_participant_file(id: usize) -> Result<Participant, Box<dyn Error>> {
    let file = File::open(format!("output/participant-{}.json", id))?;
    let reader = BufReader::new(file);
    let participant: Participant = serde_json::from_reader(reader)?;
    Ok(participant)
}

fn gen_rand_biguint() -> BigUint {
    let mut rng = thread_rng();
    // RistrettoPoint work under q ~ 2^252
    rng.gen_biguint(252)
}

fn gen_rand_scalar() -> Scalar {
    let mut csprng = rand::rngs::OsRng;
    Scalar::random(&mut csprng)
}

fn main() -> Result<(), String> {
    let args = Cli::parse();
    let fmt = &args.number_format;
    let verbose = args.verbose;

    match args.command {
        Commands::GenerateShares {
            participant_id,
            participants,
            threshold,
        } => {
            if verbose {
                println!("participant_id:   {}", participant_id);
                println!("participants:   {}", participants);
                println!("threshold: {}", threshold);
                println!("curve:     ristretto255");
            };

            generate_shares(GenerateShareParams {
                participant_id,
                participants,
                threshold,
            })
        }
        Commands::GenerateShares2 {
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
        Commands::VerifyShares { commitments, share } => {
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
        Commands::DeriveKeyShare { shares } => {
            let DeriveKeyShareResult { result: s } = derive_key_share(DeriveKeyShareParams {
                shares: shares.iter().map(|s| biguint_to_scalar(s)).collect(),
            });

            println!("Derived Key Share");
            println!("-------------------------");
            println!("{}", fmt.format(&scalar_to_biguint(&s)));

            Ok(())
        }
        Commands::FeldmanCommitments {} => {
            todo!("to be implemented")
        }
        Commands::VerifyFeldman {} => {
            todo!("to be implemented")
        }
        Commands::ReconstructShare { shares } => {
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
        Commands::ComputePublicKey {} => {
            todo!("to be implemented")
        }
    }
}

/// WARNING: if n > 252-bit value (l), function will perform n mod l
/// because Ristretto255 works under l ~ 252-bit value
fn biguint_to_scalar(n: &BigUint) -> Scalar {
    let mut b = n.to_bytes_le();
    b.resize(64, 0u8);

    let r: [u8; 64] = b[..64].try_into().expect("always 64 bytes after resize");

    Scalar::from_bytes_mod_order_wide(&r)
}

fn scalar_to_biguint(n: &Scalar) -> BigUint {
    BigUint::from_bytes_le(n.as_bytes())
}

fn biguint_to_ristretto_point(n: &BigUint) -> Result<RistrettoPoint, String> {
    let bytes = n.to_bytes_le();
    let mut buf = [0u8; 32];
    if bytes.len() > 32 {
        return Err("commitment too large for 32-byte point".into());
    }
    buf[..bytes.len()].copy_from_slice(&bytes);
    CompressedRistretto(buf)
        .decompress()
        .ok_or_else(|| format!("invalid compressed point for value {}", n))
}

fn ristretto_point_to_biguint(n: &RistrettoPoint) -> BigUint {
    BigUint::from_bytes_le(n.compress().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_cmd::Command;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_version() {
        let mut cmd = Command::cargo_bin("cli").unwrap();
        cmd.arg("--version")
            .assert()
            .success()
            .stdout(predicates::str::contains("0.1.0"));
    }

    #[test]
    fn test_generate_shares() {
        Command::cargo_bin("cli")
            .unwrap()
            .args([
                "generate-shares",
                "--secret",
                "25",
                "--players",
                "5",
                "--threshold",
                "3",
            ])
            .assert()
            .success();
    }
}
