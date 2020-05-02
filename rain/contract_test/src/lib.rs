extern crate rain_wasi_common;
extern crate bincode;
extern crate base64;

use rain_wasi_common::{Ledger, WasiDeserializable, create_result};

use std::collections::HashMap;

use wasm_bindgen::prelude::*;

pub type ContextLedger = HashMap<String, i32>;

pub fn to_context_ledger(l: Ledger) -> ContextLedger {
    let mut cl = ContextLedger::default();
    for (k,v) in l {
        let mut array = [0 as u8; 4];
        let v = &v[..array.len()];
        array.copy_from_slice(v);
        cl.insert(k, i32::from_be_bytes(array));
    }
    cl
}

pub fn to_ledger(cl: ContextLedger) -> Ledger {
    let mut l = Ledger::default();
    for (k,v) in cl {
        let mv: Vec<u8> = v.to_be_bytes().to_vec();
        l.insert(k, mv);
    }
    l
}

fn deserialize_args(enc: &str) -> (String, String, i32) {
    bincode::deserialize(&base64::decode(enc).unwrap()).unwrap()
}

#[wasm_bindgen]
pub fn execute(ledger: String, args: String) -> String {
    let mut _cl: ContextLedger = to_context_ledger(Ledger::deserialize_wasi(&ledger));
    let (_from, _to, _amount) = deserialize_args(&args);
    
    let mut from_acc: i32;
    match _cl.get(&_from) {
        None => { return create_result(Err(format!("Invalid Transaction: missing \"from\" account \"{}\"", _from))); }
        Some(v) => { from_acc = *v; }
    }

    let mut to_acc: i32;
    match _cl.get(&_to) {
        None => { return create_result(Err(format!("Invalid Transaction: missing \"to\" account \"{}\"", _to))); }
        Some(v) => { to_acc = *v; }
    }

    if from_acc >= _amount {
        from_acc -= _amount;
        to_acc += _amount;
    } else {
        return create_result(Err(format!("Invalid Transaction: insufficient funds in \"from\" account \"{}\"", _from)))
    }
 
    _cl.insert(_from, from_acc);
    _cl.insert(_to, to_acc);
   
    create_result(Ok(to_ledger(_cl)))
}