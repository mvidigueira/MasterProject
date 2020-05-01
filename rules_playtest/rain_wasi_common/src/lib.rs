extern crate bincode;
extern crate base64;

use std::collections::HashMap;

pub trait WasiSerializable {
    fn serialize_wasi(&self) -> String;
}

pub trait WasiDeserializable {
    fn deserialize_wasi(enc: &str) -> Self;
}

pub type Ledger = HashMap<String, Vec<u8>>;

impl WasiSerializable for Ledger {
    fn serialize_wasi(&self) -> String {
        base64::encode(&bincode::serialize(self).unwrap())
    }
}

impl WasiDeserializable for Ledger {
    fn deserialize_wasi(enc: &str) -> Ledger {
        bincode::deserialize(&base64::decode(enc).unwrap()).unwrap()
    }
}

pub fn extract_result(enc: &str) -> Result<Ledger, String> {
    bincode::deserialize(&base64::decode(enc).unwrap()).unwrap()
}

pub fn create_result(r: Result<Ledger, String>) -> String {
    base64::encode(&bincode::serialize(&r).unwrap())
}

pub fn serialize_args<T: serde::Serialize>(args: &T) -> String {
    serialize_args_from_byte_vec(&bincode::serialize(args).unwrap())
}

pub fn serialize_args_from_byte_vec(args: &Vec<u8>) -> String {
    base64::encode(args)
}