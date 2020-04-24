extern crate common;
extern crate bincode;
extern crate base64;

use common::records::WasiSerializable;
use common::records::extract_result;
use common::records::serialize_args;
use common::records::Ledger;

use std::collections::HashMap;

#[wasmtime_rust::wasmtime]
trait WasmContract {
    fn transfer(&mut self, records: String, args: String) -> String;
}

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

fn main() -> anyhow::Result<()> {
    let mut contract = WasmContract::load_file("contracts/target/wasm32-wasi/release/wasm_string_test.wasm")?;
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

    Ok(())
}

