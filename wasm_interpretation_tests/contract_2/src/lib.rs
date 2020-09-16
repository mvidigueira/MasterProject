use std::collections::HashMap;
//use wasm_bindgen::prelude::*;

extern crate bincode;

pub type Ledger = HashMap<String, Vec<u8>>;
pub type ContextLedger = HashMap<String, i32>;

fn to_context_ledger(l: Ledger) -> ContextLedger {
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

pub fn get_ledger(v: Vec<u8>) -> Ledger {
    bincode::deserialize(&v).unwrap()
}

pub fn create_result(r: Result<Ledger, i32>) -> Vec<u8> {
    bincode::serialize(&r).unwrap()
}

#[no_mangle]
pub fn execute(ledger: Vec<u8>, args: Vec<u8>) -> Vec<u8> {
    let mut _cl: ContextLedger = match bincode::deserialize(&ledger) {
        Ok(b) => to_context_ledger(b),
        Err(_) => return create_result(Err(0)),
    };
    let (_from, _to, _amount) = match bincode::deserialize(&args) {
        Ok((a,b,c)) => (a,b,c),
        Err(_) => return create_result(Err(0)),
    };
    
    let mut from_acc: i32;
    match _cl.get(&_from) {
        None => { return create_result(Err(1)); }
        Some(v) => { from_acc = *v; }
    }

    let mut to_acc: i32;
    match _cl.get(&_to) {
        None => { return create_result(Err(2)); }
        Some(v) => { to_acc = *v; }
    }

    if from_acc >= _amount {
        from_acc -= _amount;
        to_acc += _amount;
    } else {
        return create_result(Err(3))
    }
 
    _cl.insert(_from, from_acc);
    _cl.insert(_to, to_acc);
   
    create_result(Ok(to_ledger(_cl)))
}