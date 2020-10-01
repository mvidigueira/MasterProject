#![feature(vec_into_raw_parts)]

use std::collections::HashMap;

use drop::crypto::sign::{PublicKey, Signature, Signer};

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
    let (_requester, from, to, amount) = deserialize_args(args);

    let mut from_acc: i32 = 0;
    match cl.get(&from) {
        None => {}
        Some(v) => { from_acc = *v; }
    }

    let mut to_acc: i32 = 0;
    match cl.get(&to) {
        None => {}
        Some(v) => { to_acc = *v; }
    }

    if from_acc >= amount {
        from_acc -= amount;
        to_acc += amount;
    }
 
    cl.insert(from, from_acc);
    cl.insert(to, to_acc);

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

fn to_ledger(cl: ContextLedger) -> Ledger {
    let mut l = Ledger::default();
    for (k,v) in cl {
        let mv: Vec<u8> = v.to_be_bytes().to_vec();
        l.insert(k, mv);
    }
    l
}

fn deserialize_args(v: Vec<u8>) -> (String, String, String, i32) {
    bincode::deserialize(&v).unwrap()
}