use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;

use num_bigint::BigUint;
use serde::Deserialize;
use serde::Serialize;
use utils::biguint_to_hex;
use utils::hex_to_biguint;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantShare {
    pub s: String,
    pub u: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ParticipantGenerated {
    pub id: usize,
    pub pedersen_commitments: Vec<String>,
    pub feldman_commitments: Vec<String>,
    pub shares_to: HashMap<String, ParticipantShare>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ParticipantReceived {
    pub pedersen_commitments: HashMap<String, Vec<String>>,
    pub feldman_commitments: HashMap<String, Vec<String>>,
    pub shares_from: HashMap<String, ParticipantShare>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ParticipantDerived {
    pub share_key: String,
    pub public_key: Option<String>,
}

pub struct ParticipantFiles {
    pub generated_filepath: String,
    pub received_filepath: String,
    pub derived_filepath: String,
}

impl ParticipantFiles {
    pub fn new(id: usize) -> Self {
        ParticipantFiles {
            generated_filepath: format!("output/participant-{}/generated.json", id),
            received_filepath: format!("output/participant-{}/received.json", id),
            derived_filepath: format!("output/participant-{}/derived.json", id),
        }
    }

    pub fn write_generated(
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

    pub fn read_generated(&self) -> Result<ParticipantGenerated, Box<dyn Error>> {
        let file = File::open(&self.generated_filepath)?;
        let reader = BufReader::new(file);
        let participant: ParticipantGenerated = serde_json::from_reader(reader)?;
        Ok(participant)
    }

    pub fn ensure_received_file_exists(&self) -> Result<File, Box<dyn Error>> {
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

    pub fn append_received(
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

    pub fn read_received(&self) -> Result<ParticipantReceived, String> {
        let file = File::open(&self.received_filepath)
            .map_err(|e| format!("cannot open received file, error: {}", e))?;
        let reader = BufReader::new(file);
        let result: ParticipantReceived = serde_json::from_reader(reader)
            .map_err(|e| format!("cannot read received file, error: {}", e))?;
        Ok(result)
    }

    pub fn ensure_derived_file(&self) -> Result<File, String> {
        // create file for write
        let mut file = OpenOptions::new()
            .write(true)
            .create(true) // Create if missing; do nothing if exists
            .open(self.derived_filepath.as_str())
            .map_err(|e| format!("cannot open derived file, error: {}", e))?;

        let read = self.read_derived();
        if read.is_ok() {
            return Ok(file);
        }

        // ensure parent dir is created
        let path = Path::new(self.derived_filepath.as_str());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "cannot create participant folder for derived file, error: {}",
                    e
                )
            })?;
        }

        // write default data if file is new created
        let metadata = file
            .metadata()
            .map_err(|e| format!("cannot read derived file metadata, error: {}", e))?;
        if metadata.len() == 0 {
            let default = ParticipantDerived {
                share_key: String::new(),
                public_key: None,
            };
            let json_data = serde_json::to_string_pretty(&default)
                .map_err(|e| format!("cannot serialize default derived file data, error: {}", e))?;
            file.write_all(json_data.as_bytes())
                .map_err(|e| format!("cannot write default data to derived file, error: {}", e))?;
        }

        Ok(file)
    }

    pub fn read_derived(&self) -> Result<ParticipantDerived, String> {
        let file = File::open(&self.derived_filepath)
            .map_err(|e| format!("cannot open derived file, error: {}", e))?;
        let reader = BufReader::new(file);
        let result: ParticipantDerived = serde_json::from_reader(reader)
            .map_err(|e| format!("cannot read derived file, error: {}", e))?;
        Ok(result)
    }

    pub fn read_share_key(&self) -> Result<BigUint, String> {
        let derived = self.read_derived()?;
        Ok(hex_to_biguint(&derived.share_key)?)
    }

    pub fn write_share_key(&self, value: &BigUint) -> Result<(), String> {
        // ensure file data is created
        self.ensure_derived_file()?;

        // read and update data
        let mut data = self.read_derived()?;
        data.share_key = biguint_to_hex(value);

        // overwrite with new data
        let file = File::create(self.derived_filepath.to_string()).map_err(|e| {
            format!(
                "attempt to createa and truncate derived file to write new data, got error: {}",
                e
            )
        })?; // File::create also truncates
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &data)
            .map_err(|e| format!("cannot write derived data, error: {}", e))?;
        Ok(())
    }

    pub fn write_public_key(&self, value: &BigUint) -> Result<(), String> {
        // ensure file data is created
        self.ensure_derived_file()?;

        // read and update data
        let mut data = self.read_derived()?;
        data.public_key = Some(biguint_to_hex(value));

        // overwrite with new data
        let file = File::create(self.derived_filepath.to_string()).map_err(|e| {
            format!(
                "attempt to createa and truncate derived file to write new data, got error: {}",
                e
            )
        })?; // File::create also truncates
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &data)
            .map_err(|e| format!("cannot write derived data, error: {}", e))?;
        Ok(())
    }
}
