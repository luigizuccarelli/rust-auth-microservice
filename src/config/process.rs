use serde_derive::{Deserialize, Serialize};
use std::fs::File;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Parameters {
    pub name: String,
    pub description: String,
    pub port: String,
    pub log_level: String,
    pub certs_dir: Option<String>,
    pub cert_mode: String,
    pub user_api_url: String,
}

pub trait ConfigInterface {
    fn read(&self, dir: String) -> Result<Parameters, Box<dyn std::error::Error>>;
}

#[derive(Debug, Clone)]
pub struct ImplConfigInterface {}

impl ConfigInterface for ImplConfigInterface {
    fn read(&self, name: String) -> Result<Parameters, Box<dyn std::error::Error>> {
        let json_data = File::open(&name);
        if json_data.is_err() {
            return Err(Box::from("config file not found"));
        }
        let params = serde_json::from_reader(json_data.unwrap());
        if params.is_err() {
            return Err(Box::from(format!(
                "parsing config file {}",
                params.err().unwrap()
            )));
        }
        Ok(params.unwrap())
    }
}
