extern crate common;

use common::records::Record;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn run1() -> String {
    let r = Record{k: "Alice".to_string(), v: [42].to_vec()};
    r.to_base64()
}