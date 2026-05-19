use std::collections::HashMap;
use std::collections::HashSet;
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
    // new field that will be used to refactor received structure
    pub data: Option<HashMap<String, ParticipantSent>>,
}

// new struct for received data that will be use
// to refactor the receive data
#[derive(Serialize, Deserialize, Debug)]
pub struct ParticipantSent {
    pub complaint_pedersen: HashSet<String>,

    // for_participant_id --> share
    pub justification: Option<Justification>,
}

pub type Justification = HashMap<String, ParticipantShare>;

#[derive(Serialize, Deserialize, Debug)]
pub struct ParticipantDerived {
    pub share_key: String,
    pub public_key: Option<String>,
    pub complaint_pedersen: Option<HashSet<String>>,
}

pub struct Output {
    id: usize,
    generated_filepath: String,
    received_filepath: String,
    derived_filepath: String,
}

impl Output {
    pub fn new(id: usize) -> Self {
        Output {
            id,
            generated_filepath: format!("output/participant-{}/generated.json", id),
            received_filepath: format!("output/participant-{}/received.json", id),
            derived_filepath: format!("output/participant-{}/derived.json", id),
        }
    }

    pub fn write_generated(
        &self,
        id: usize,
        pedersen_commitments: Vec<String>,
        feldman_commitments: Vec<String>,
        shares_to: HashMap<String, ParticipantShare>,
    ) -> Result<(), Box<dyn Error>> {
        let path = Path::new(self.generated_filepath.as_str());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(
            writer,
            &ParticipantGenerated {
                id,
                pedersen_commitments,
                feldman_commitments,
                shares_to,
            },
        )?;
        Ok(())
    }

    pub fn read_generated(&self) -> Result<ParticipantGenerated, String> {
        let file = File::open(&self.generated_filepath).map_err(|e| {
            format!(
                "cannot open generated file {}, error: {}",
                self.generated_filepath, e
            )
        })?;
        let reader = BufReader::new(file);
        let participant: ParticipantGenerated = serde_json::from_reader(reader).map_err(|e| {
            format!(
                "cannot read generated file {}, error: {}",
                self.generated_filepath, e
            )
        })?;
        Ok(participant)
    }

    pub fn ensure_received_file_exists(&self) -> Result<File, String> {
        // ensure parent dir is created
        let path = Path::new(self.received_filepath.as_str());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "cannot create parent folder for {}, error: {}",
                    self.received_filepath, e
                )
            })?;
        }

        // create file for write
        let mut file = OpenOptions::new()
            .write(true)
            .create(true) // Create if missing; do nothing if exists
            .open(self.received_filepath.as_str())
            .map_err(|e| format!("cannot open file {}, error: {}", self.received_filepath, e))?;

        // write default data if file is new created
        let metadata = file.metadata().map_err(|e| {
            format!(
                "cannot read metadata of file {}, error: {}",
                self.received_filepath, e
            )
        })?;
        if metadata.len() == 0 {
            let default = ParticipantReceived {
                pedersen_commitments: HashMap::new(),
                feldman_commitments: HashMap::new(),
                shares_from: HashMap::new(),
                data: None,
            };
            let json_data = serde_json::to_string_pretty(&default).map_err(|e| {
                format!(
                    "cannot serialize data for {}, error: {}",
                    self.received_filepath, e
                )
            })?;
            file.write_all(json_data.as_bytes()).map_err(|e| {
                format!(
                    "cannot write data for {}, error: {}",
                    self.received_filepath, e
                )
            })?;
        }

        Ok(file)
    }

    pub fn append_received(
        &self,
        from_participant_id: String,
        pedersent_commitments: Vec<String>,
        feldman_commitments: Vec<String>,
        shares: ParticipantShare,
    ) -> Result<(), String> {
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
        self.write_received(&result)
    }

    fn write_received(&self, received: &ParticipantReceived) -> Result<(), String> {
        // overwrite with new data
        let file = File::create(self.received_filepath.to_string()).map_err(|e| {
            format!(
                "cannot create file {}, error: {}",
                self.received_filepath, e
            )
        })?; // File::create also truncates
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &received).map_err(|e| {
            format!(
                "cannot write data to file {}, error {}",
                self.received_filepath, e
            )
        })?;
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
                complaint_pedersen: None,
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

    fn write_derived(&self, data: &ParticipantDerived) -> Result<(), String> {
        // overwrite with new data
        let file = File::create(self.derived_filepath.to_string()).map_err(|e| {
            format!(
                "attempt to createa and truncate derived file to write new data, got error: {}",
                e
            )
        })?; // file::create also truncates
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, data)
            .map_err(|e| format!("cannot write derived data, error: {}", e))?;
        Ok(())
    }

    pub fn save_complaint_pedersen(&self, against: String) -> Result<(), String> {
        // ensure file data is created
        self.ensure_derived_file()?;

        // read and update data
        let mut data = self.read_derived()?;
        let mut newData: HashSet<String> = data.complaint_pedersen.unwrap_or(HashSet::new());
        newData.insert(against);
        data.complaint_pedersen = Some(newData);

        self.write_derived(&data)
    }

    pub fn write_share_key(&self, value: &BigUint) -> Result<(), String> {
        // ensure file data is created
        self.ensure_derived_file()?;

        // read and update data
        let mut data = self.read_derived()?;
        data.share_key = biguint_to_hex(value);

        self.write_derived(&data)
    }

    pub fn write_public_key(&self, value: &BigUint) -> Result<(), String> {
        // ensure file data is created
        self.ensure_derived_file()?;

        // read and update data
        let mut data = self.read_derived()?;
        data.public_key = Some(biguint_to_hex(value));

        self.write_derived(&data)
    }

    pub fn send_complaint_pedersen(&self, to: usize, against: String) -> Result<(), String> {
        let receiver = Output::new(to);
        receiver.received_complaint_pedersen(self.id, against)
    }

    pub fn received_complaint_pedersen(&self, from: usize, against: String) -> Result<(), String> {
        self.ensure_received_file_exists()?;
        let mut received = self.read_received()?;
        let data = received.data.get_or_insert(HashMap::new());
        let sent = data.entry(format!("{}", from)).or_insert(ParticipantSent {
            complaint_pedersen: HashSet::new(),
            justification: None,
        });
        sent.complaint_pedersen.insert(against);

        self.write_received(&received)
    }

    pub fn send_justification(
        &self,
        to: usize,
        complaintor: String,
        shares: ParticipantShare,
    ) -> Result<(), String> {
        let receiver = Output::new(to);
        receiver.receive_justify_commitment(self.id, complaintor, shares)
    }

    pub fn receive_justify_commitment(
        &self,
        from: usize,
        complaintor: String,
        share: ParticipantShare,
    ) -> Result<(), String> {
        self.ensure_received_file_exists()?;
        let mut received = self.read_received()?;
        let data = received.data.get_or_insert(HashMap::new());
        let sent = data.entry(from.to_string()).or_insert(ParticipantSent {
            complaint_pedersen: HashSet::new(),
            justification: Some(HashMap::new()),
        });
        let justification = sent.justification.get_or_insert(HashMap::new());

        justification.insert(complaintor, share);

        self.write_received(&received)
    }
}
