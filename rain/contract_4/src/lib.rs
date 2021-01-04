#![feature(vec_into_raw_parts)]

use std::collections::HashMap;

use ed25519_dalek::{PublicKey, Signature, Verifier};
use wasm_common_bindings::{Ledger, Args};
use bincode;

pub type ContextLedger = HashMap<String, (i32, (PublicKey, i32))>;

#[no_mangle]
pub extern "C" fn allocate_vec(length: i32) -> *mut u8 {
    let v = Vec::with_capacity(length as usize);
    v.into_raw_parts().0
}

#[no_mangle]
pub extern "C" fn execute(ptr: *mut u8, length: i32) -> *mut u8 {
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
    return make_result(l);
}

// HELPERS

fn parse_input(ptr: *mut u8, length: i32) -> (Ledger, Args) {
    let v: Vec<u8> = unsafe {
        Vec::from_raw_parts(ptr, length as usize, length as usize)
    };

    wasm_common_bindings::get_input(v)
}

fn make_result(l: Ledger) -> *mut u8 {
    let (ptr, len, _) = wasm_common_bindings::create_result(l).into_raw_parts();

    [(len as i32).to_be_bytes(), (ptr as i32).to_be_bytes()]
    .concat()
    .as_mut_ptr()
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