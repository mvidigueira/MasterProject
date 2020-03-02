extern crate serde;
extern crate bincode;
extern crate base64;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Record {
    pub k: String,
    pub v: Vec<u8>,
}

impl Record {
    pub fn to_base64(&self) -> String {
        base64::encode(&bincode::serialize(&self).unwrap())
    }

    pub fn from_base64(s: &str) -> Record {
        bincode::deserialize(&base64::decode(s).unwrap()).unwrap()
    }
}
