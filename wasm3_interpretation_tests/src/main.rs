use wasm3::Environment;
use wasm3::Module;

use wasm_common_bindings::{ContextLedger};

fn main() {
    let file = "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
    let bytes = std::fs::read(file).unwrap();

    let env = Environment::new().expect("Unable to create environment");
        
    // RUNTIME CREATION

    let rt = env
    .create_runtime(1024 * 60)
    .expect("Unable to create runtime");
    
    // LOADING

    let module = Module::parse(&env, &bytes)
    .expect("Unable to parse module");
    
    let module = rt.load_module(module).expect("Unable to load module");

    // EXECUTION
    let allocate = module
        .find_function::<i32, i32>("allocate_vec")
        .expect("Unable to find function");

    let execute = module
        .find_function::<(i32, i32), i32>("execute")
        .expect("Unable to find function");
        
    let mut cl = ContextLedger::new();
    cl.insert("Alice".to_string(), 50);
    cl.insert("Dave".to_string(), 50);
    let l = wasm_common_bindings::to_ledger(cl);

    let args = ("Alice".to_string(), "Alice".to_string(), "Dave".to_string(), 50 as i32);
    let input = wasm_common_bindings::create_input(l, &args);
    let len = input.len();

    let ptr = allocate.call(len as i32).unwrap();

    let s = unsafe {
        &mut *rt.memory_mut()
    };

    s[ptr as usize .. ptr as usize + len].copy_from_slice(input.as_ref());

    let ptr = execute.call(ptr, len as i32).unwrap();
    let s = unsafe {
        &*rt.memory_mut()
    };

    let l = wasm_common_bindings::get_result(s, ptr);
    let cl = wasm_common_bindings::to_context_ledger(l);

    println!("Ledger {:?}", &cl);

    // let mut len: [u8; 4] = [0; 4];
    // let mut pointer: [u8; 4] = [0; 4];

    // let s = unsafe {
    //     &*rt.memory()
    // };

    // len.copy_from_slice(&s[ptr as usize.. ptr as usize + std::mem::size_of::<i32>()]);
    // pointer.copy_from_slice(&s[ptr as usize + std::mem::size_of::<i32>()
    // .. ptr as usize + 2*std::mem::size_of::<i32>()]);
    // let len = i32::from_be_bytes(len) as usize;
    // let pointer = i32::from_be_bytes(pointer);

    // let v: Vec<u8> = s[pointer as usize .. pointer as usize + len].to_vec();
    
    // println!("vec is {:?}", &v);
}
