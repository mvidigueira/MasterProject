use std::collections::HashMap;

use ed25519_dalek::{PublicKey, Signature, Verifier};
use wasm_common_bindings::{Ledger, Args};
use bincode;

pub type ContextLedger = HashMap<String, (i32, (PublicKey, i32))>;

pub fn allocate_vec_sim(length: i32) -> *mut u8 {
    let v = Vec::with_capacity(length as usize);
    v.into_raw_parts().0
}

pub fn execute_sim(ptr: *mut u8, length: i32) -> Ledger {
    let (l, args) = parse_input(ptr, length);
    let mut cl = to_context_ledger(l);

    let (from, to, amount, nonce) = validate(&cl, args);

    if cl.contains_key(&from) && cl.contains_key(&to) && cl.get(&from).unwrap().1.1 == nonce && cl.get(&from).unwrap().0 >= amount {
        if let Some(a) = cl.get_mut(&from) {
            a.0 -= amount;
            a.1.1 += 1;
        }

        if let Some(b) = cl.get_mut(&to) {
            b.0 += amount;
        }
    }

    let l = to_ledger(cl);
    l
}

// HELPERS

fn parse_input(ptr: *mut u8, length: i32) -> (Ledger, Args) {
    let v: Vec<u8> = unsafe {
        Vec::from_raw_parts(ptr, length as usize, length as usize)
    };

    wasm_common_bindings::get_input(v)
}

pub fn to_context_ledger(l: Ledger) -> ContextLedger {
    let mut cl = ContextLedger::default();
    for (k,v) in l {
        let v: (i32, (PublicKey, i32)) = bincode::deserialize(&v).unwrap();
        cl.insert(k, v);
    }
    cl
}

pub fn to_ledger(cl: ContextLedger) -> Ledger {
    let mut l = Ledger::default();
    for (k,v) in cl {
        let mv: Vec<u8> = bincode::serialize(&v).unwrap();
        l.insert(k, mv);
    }
    l
}
fn deserialize_args(v: Vec<u8>) -> (String, String, i32, Signature) {
    bincode::deserialize(&v).unwrap()
}

fn validate(cl: &ContextLedger, args: Vec<u8>) -> (String, String, i32, i32) {
    let (from, to, amount, sig) = deserialize_args(args);
    let (_, (pk, nonce)) = cl.get(&from).unwrap();

    let temp = (from, to, amount, *nonce);
    pk.verify(&bincode::serialize(&temp).unwrap(), &sig).unwrap();

    temp
}