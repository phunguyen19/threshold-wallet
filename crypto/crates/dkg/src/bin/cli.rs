use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::ops::Deref;
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
    /// Read participant received file and verify the shares and commitments
    /// received from each of other participants
    VerifyShares {
        /// Participant ID that will be read data from
        #[arg(long, short)]
        participant_id: usize,
    },
    /// Derive key share of each play from received shares by other players.
    /// x_i = sum(s_ji)
    DeriveKeyShare {
        #[arg(long, short, value_delimiter = ':', value_parser = cli_parse_biguint)]
        shares: Vec<BigUint>,
    },
    /// Generate Feldman Commitments and broadcast to all players
    /// A_ik = g^a_ik (for k = 0,...t of coeff-th of polynomial f)
    FeldmanCommitments {},
    ///
    VerifyFeldman {},
    ReconstructShare {
        /// List of shares for reconstruct the secret
        #[arg(long, short, value_parser = cli_parse_reconstruct_shares_param)]
        shares: Vec<(BigUint, BigUint)>,
    },
    ComputePublicKey {},
}

#[derive(Debug)]
struct DeriveKeyShareParams {
    shares: Vec<Scalar>,
}

#[derive(Debug)]
struct DeriveKeyShareResult {
    result: Scalar,
}

struct GenerateShareParams {
    participant_id: usize,
    participants: usize,
    threshold: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct ParticipantGenerated {
    id: usize,
    pedersen_commitments: Vec<String>,
    feldman_commitments: Vec<String>,
    shares_to: HashMap<String, ParticipantShare>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ParticipantShare {
    s: String,
    u: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ParticipantReceived {
    pedersen_commitments: HashMap<String, Vec<String>>,
    feldman_commitments: HashMap<String, Vec<String>>,
    shares_from: HashMap<String, ParticipantShare>,
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

    fn ensure_received_file_exists(&self) -> Result<File, Box<dyn Error>> {
        // ensure parent dir is created
        let path = Path::new(self.received_filepath.as_str());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // create file for write
        let mut file = OpenOptions::new()
            .write(true)
            .create(true) // Create if missing; do nothing if exists
            .open(self.received_filepath.as_str())?;

        // write default data if file is new created
        let metadata = file.metadata()?;
        if metadata.len() == 0 {
            let default = ParticipantReceived {
                pedersen_commitments: HashMap::new(),
                feldman_commitments: HashMap::new(),
                shares_from: HashMap::new(),
            };
            let json_data = serde_json::to_string_pretty(&default)?;
            file.write_all(json_data.as_bytes())?;
        }

        Ok(file)
    }

    fn append_received(
        &self,
        from_participant_id: String,
        pedersent_commitments: Vec<String>,
        feldman_commitments: Vec<String>,
        shares: ParticipantShare,
    ) -> Result<(), Box<dyn Error>> {
        // ensure file is created
        self.ensure_received_file_exists()?;

        // read received to append data
        let mut result = self.read_received()?;

        // append/override data
        result
            .shares_from
            .insert(from_participant_id.clone(), shares);
        result
            .pedersen_commitments
            .insert(from_participant_id.clone(), pedersent_commitments);
        result
            .feldman_commitments
            .insert(from_participant_id.clone(), feldman_commitments);

        // overwrite with new data
        let file = File::create(self.received_filepath.to_string())?; // File::create also truncates
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &result)?;
        Ok(())
    }

    fn read_received(&self) -> Result<ParticipantReceived, Box<dyn Error>> {
        let file = File::open(&self.received_filepath)?;
        let reader = BufReader::new(file);
        let result: ParticipantReceived = serde_json::from_reader(reader)?;
        Ok(result)
    }
}

fn cli_parse_reconstruct_shares_param(val: &str) -> Result<(BigUint, BigUint), String> {
    let s: Vec<&str> = val.split(':').collect();
    if s.len() != 2 {
        return Err(format!("cannot parse share param: {:?}", val));
    }

    let x = match cli_parse_biguint(s[0]) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "cannot parse x={} of share={:?} error: {:?}",
                s[0], val, e
            ));
        }
    };

    let y = match cli_parse_biguint(s[1]) {
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

fn cli_parse_biguint(s: &str) -> Result<BigUint, String> {
    if let Some(x) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        BigUint::from_str_radix(x, 16).map_err(|e| e.to_string())
    } else {
        BigUint::from_str_radix(s, 10).map_err(|e| e.to_string())
    }
}

fn command_handler_generate_shares(params: GenerateShareParams) -> Result<(), String> {
    if params.participant_id < 1 || params.participant_id > params.participants {
        return Err(format!("participant_id is not valid"));
    }

    let random_secret = gen_rand_biguint();

    let pedersen_deal_result = vss::deal(vss::DealParams {
        secret: random_secret,
        players: params.participants,
        threshold: params.threshold,
    })?;

    // Feldman commitments
    let feldman_commitments = feldman_commitments(pedersen_deal_result.coeffs_a);

    let participant_files = ParticipantFiles::new(params.participant_id);

    let mut shares_hashmap: HashMap<String, ParticipantShare> = HashMap::new();
    for share in pedersen_deal_result.shares {
        shares_hashmap.insert(
            share.0.to_string(),
            ParticipantShare {
                s: biguint_to_hex(&share.1),
                u: biguint_to_hex(&share.2),
            },
        );
    }

    for i in 1..=params.participants {
        let participant_received_files = ParticipantFiles::new(i);
        let received_share = shares_hashmap.get(&i.to_string()).cloned().unwrap();
        participant_received_files
            .append_received(
                params.participant_id.to_string(),
                pedersen_deal_result
                    .commitments
                    .iter()
                    .map(|v| biguint_to_hex(&v))
                    .collect(),
                feldman_commitments
                    .iter()
                    .map(|v| biguint_to_hex(&v))
                    .collect(),
                received_share,
            )
            .unwrap();
    }

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
            shares_to: shares_hashmap,
        })
        .expect("write generated result fail");

    println!("{:?}", participant_files.read_generated());

    Ok(())
}

fn command_handler_derive_key_share(params: DeriveKeyShareParams) -> DeriveKeyShareResult {
    DeriveKeyShareResult {
        result: params
            .shares
            .iter()
            .fold(Scalar::ZERO, |sum, share| sum + share),
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

            command_handler_generate_shares(GenerateShareParams {
                participant_id,
                participants,
                threshold,
            })
        }
        Commands::VerifyShares { participant_id } => Ok(()),
        Commands::DeriveKeyShare { shares } => {
            let DeriveKeyShareResult { result: s } =
                command_handler_derive_key_share(DeriveKeyShareParams {
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
