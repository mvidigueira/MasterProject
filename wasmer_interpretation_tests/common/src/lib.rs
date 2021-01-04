extern crate bincode;

use ed25519_dalek::{PublicKey};
use std::collections::HashMap;

pub type Ledger = HashMap<String, Vec<u8>>;
pub type Args = Vec<u8>;
pub type Input = (Ledger, Args);

pub fn create_result(s: Ledger) -> Vec<u8> {
    bincode::serialize(&s).unwrap()
}

pub fn get_result(base: &[u8], ptr: i32) -> Ledger {
    let mut len: [u8; 4] = [0; 4];
    let mut pointer: [u8; 4] = [0; 4];

    len.copy_from_slice(&base[ptr as usize .. ptr as usize + std::mem::size_of::<i32>()]);
    pointer.copy_from_slice(&base[ptr as usize + std::mem::size_of::<i32>() .. ptr as usize + 2*std::mem::size_of::<i32>()]);

    let len = i32::from_be_bytes(len) as usize;
    let ptr = i32::from_be_bytes(pointer);

    let v: Vec<u8> = base[ptr as usize .. ptr as usize + len].to_vec();
    bincode::deserialize(&v).unwrap()
}

pub fn create_input<T: serde::Serialize>(l: Ledger, args: &T) -> Vec<u8> {
    bincode::serialize(&(l, bincode::serialize(args).unwrap())).unwrap()
}

pub fn get_input(v: Vec<u8>) -> (Ledger, Args) {
    bincode::deserialize(&v).unwrap()
}

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

pub type ContextLedger2 = HashMap<String, (i32, (PublicKey, i32))>;

pub fn to_context_ledger_2(l: Ledger) -> ContextLedger2 {
    let mut cl = ContextLedger2::default();
    for (k,v) in l {
        let v: (i32, (PublicKey, i32)) = bincode::deserialize(&v).unwrap();
        cl.insert(k, v);
    }
    cl
}

pub fn to_ledger_2(cl: ContextLedger2) -> Ledger {
    let mut l = Ledger::default();
    for (k,v) in cl {
        let mv: Vec<u8> = bincode::serialize(&v).unwrap();
        l.insert(k, mv);
    }
    l
}