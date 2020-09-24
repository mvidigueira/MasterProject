extern crate bincode;

use std::collections::HashMap;

pub type Ledger = HashMap<String, Vec<u8>>;
pub type Args = Vec<u8>;
pub type Input = (Ledger, Args);

pub fn create_result(s: Ledger) -> Vec<u8> {
    bincode::serialize(&s).unwrap()
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