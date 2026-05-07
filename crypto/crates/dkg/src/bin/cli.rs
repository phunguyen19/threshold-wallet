use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::path::Path;

use clap::{Parser, Subcommand, ValueEnum};
use curve25519_dalek::Scalar;
use dkg::biguint_to_hex;
use dkg::biguint_to_scalar;
use dkg::feldman_commitments;
use dkg::gen_rand_biguint;
use dkg::scalar_to_biguint;
use num_bigint::BigUint;
use num_traits::Num;
use serde::Deserialize;
use serde::Serialize;

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

    let pedersen_deal_result = vss::deal(vss::DealParams {
        secret: random_secret,
        players: params.participants,
        threshold: params.threshold,
    })?;

    // Feldman commitments
    let feldman_commitments = feldman_commitments(pedersen_deal_result.coeffs_a);

    let participant_files = ParticipantFiles::new(params.participant_id);

    participant_files
        .write_generated(ParticipantGenerated {
            id: params.participant_id,
            pedersen_commitments: pedersen_deal_result
                .commitments
                .iter()
                .map(|v| biguint_to_hex(&v))
                .collect(),
            feldman_commitments: feldman_commitments
                .iter()
                .map(|v| biguint_to_hex(&v))
                .collect(),
            shares: pedersen_deal_result
                .shares
                .iter()
                .map(|v| ParticipantShare {
                    id: v.0,
                    s: biguint_to_hex(&v.1),
                    u: biguint_to_hex(&v.2),
                })
                .collect(),
        })
        .expect("write generated result fail");

    println!("{:?}", participant_files.read_generated());

    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
struct ParticipantGenerated {
    id: usize,
    pedersen_commitments: Vec<String>,
    feldman_commitments: Vec<String>,
    shares: Vec<ParticipantShare>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ParticipantShare {
    id: usize,
    s: String,
    u: String,
}

struct ParticipantFiles {
    generated_filepath: String,
    received_filepath: String,
}

impl ParticipantFiles {
    fn new(id: usize) -> Self {
        ParticipantFiles {
            generated_filepath: format!("output/participant-{}/generated.json", id),
            received_filepath: format!("output/participant-{}/received.json", id),
        }
    }
    fn write_generated(
        &self,
        participant_generated: ParticipantGenerated,
    ) -> Result<(), Box<dyn Error>> {
        let path = Path::new(self.generated_filepath.as_str());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &participant_generated)?;
        Ok(())
    }

    fn read_generated(&self) -> Result<ParticipantGenerated, Box<dyn Error>> {
        let file = File::open(&self.generated_filepath)?;
        let reader = BufReader::new(file);
        let participant: ParticipantGenerated = serde_json::from_reader(reader)?;
        Ok(participant)
    }
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
