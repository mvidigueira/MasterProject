extern crate rain_wasi_common;
extern crate bincode;
extern crate base64;

use rain_wasi_common::{WasiSerializable, Ledger, extract_result, serialize_args};

use std::collections::HashMap;

use rain_wasmtime_contract::WasmContract;

fn to_ledger(cl: HashMap<String, i32>) -> Ledger {
    let mut l = Ledger::default();
    for (k,v) in cl {
        let mv: Vec<u8> = v.to_be_bytes().to_vec();
        l.insert(k, mv);
    }
    l
}

fn to_context_ledger(l: Ledger) -> HashMap<String, i32> {
    let mut cl: HashMap<String, i32> = HashMap::default();
    for (k,v) in l {
        let mut array = [0 as u8; 4];
        let v = &v[..array.len()];
        array.copy_from_slice(v);
        cl.insert(k, i32::from_be_bytes(array));
    }
    cl
}

fn main() {
    let filename = "contracts/target/wasm32-wasi/release/wasm_string_test.wasm";
    let buffer = std::fs::read(filename).expect("could not load file into buffer");

    let mut contract = WasmContract::load_bytes(buffer).expect("failed to load bytes");
    //let mut contract = WasmContract::load_file("contracts/target/wasm32-wasi/release/wasm_string_test.wasm").expect("failed to load file");
    let args = serialize_args(&("Alice".to_string(), "Alice".to_string(), "Bob".to_string(), 50 as i32));

    let mut c_ledger: HashMap<String, i32> = HashMap::new();
    c_ledger.insert("Alice".to_string(), 100);
    c_ledger.insert("Bob".to_string(), 0);
    let ledger: Ledger = to_ledger(c_ledger);
    
    let y = &contract.transfer(ledger.serialize_wasi(), args);
    match extract_result(y) {
        Err(s) => println!("Error: {}", s),
        Ok(l) => println!("{:#?}", to_context_ledger(l))
    };
}

