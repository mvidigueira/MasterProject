#![feature(test)]
#![feature(vec_into_raw_parts)]

#[cfg(test)]
mod test {
    extern crate test;
    use test::Bencher;
    
    use wasm_common_bindings::{ContextLedger, Ledger};
    use wasmer_runtime::{imports, Func, memory::MemoryView};

    fn get_result(base: &MemoryView<u8>, ptr: i32) -> Ledger {
        let base = base[..].iter().map(|x| x.get()).collect::<Vec<u8>>();
    
        let mut len: [u8; 4] = [0; 4];
        let mut pointer: [u8; 4] = [0; 4];
    
        len.copy_from_slice(&base[ptr as usize .. ptr as usize + std::mem::size_of::<i32>()]);
        pointer.copy_from_slice(&base[ptr as usize + std::mem::size_of::<i32>() .. ptr as usize + 2*std::mem::size_of::<i32>()]);
    
        let len = i32::from_be_bytes(len) as usize;
        let ptr = i32::from_be_bytes(pointer);
    
        let v: Vec<u8> = base[ptr as usize .. ptr as usize + len].to_vec();
        bincode::deserialize(&v).unwrap()
    }

    #[bench]
    fn test_singlepass(b: &mut Bencher) {
        use wasmer_singlepass_backend::SinglePassCompiler;

        let file = "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let bytes = std::fs::read(file).unwrap();
    
        b.iter(|| {
            let module = wasmer_runtime::compile_with(&bytes, &SinglePassCompiler::new()).unwrap();

            let import_object = imports! {};
            let instance = module.instantiate(&import_object).unwrap();

            let allocate: Func<i32, i32> = instance.exports
            .get("allocate_vec")
            .expect("Unable to find function");

            let execute: Func<(i32, i32), i32> = instance.exports
            .get("execute")
            .expect("Unable to find function");
            
            let mut cl = ContextLedger::new();
            cl.insert("Alice".to_string(), 50);
            cl.insert("Dave".to_string(), 50);
            let l = wasm_common_bindings::to_ledger(cl);

            let args = ("Alice".to_string(), "Alice".to_string(), "Dave".to_string(), 50 as i32);
            let input = wasm_common_bindings::create_input(l, &args);
            let len = input.len();

            let ptr = allocate.call(len as i32).unwrap();
            println!("ptr: {:?}", ptr);

            let s: MemoryView<u8> = instance.context().memory(0).view();

            for (i, v) in input.iter().enumerate() {
                s[ptr as usize + i].replace(*v);
            }

            // s[ptr as usize .. ptr as usize + len].iter().map(|x| x.get()).collect::<Vec<u8>>().copy_from_slice(input.as_ref());

            let ptr = execute.call(ptr, len as i32).unwrap();
            let s: MemoryView<u8> = instance.context().memory(0).view();

            let l = get_result(&s, ptr);
            // let cl = wasm_common_bindings::to_context_ledger(l);
        });

        // println!("Ledger {:?}", &cl);
    }

    #[bench]
    fn test_cranelift(b: &mut Bencher) {
        let file = "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let bytes = std::fs::read(file).unwrap();
    
        b.iter(|| {
            let module = wasmer_runtime::compile_with(&bytes, &wasmer_runtime::default_compiler()).unwrap();

            let import_object = imports! {};
            let instance = module.instantiate(&import_object).unwrap();

            let allocate: Func<i32, i32> = instance.exports
            .get("allocate_vec")
            .expect("Unable to find function");

            let execute: Func<(i32, i32), i32> = instance.exports
            .get("execute")
            .expect("Unable to find function");
            
            let mut cl = ContextLedger::new();
            cl.insert("Alice".to_string(), 50);
            cl.insert("Dave".to_string(), 50);
            let l = wasm_common_bindings::to_ledger(cl);

            let args = ("Alice".to_string(), "Alice".to_string(), "Dave".to_string(), 50 as i32);
            let input = wasm_common_bindings::create_input(l, &args);
            let len = input.len();

            let ptr = allocate.call(len as i32).unwrap();
            println!("ptr: {:?}", ptr);

            let s: MemoryView<u8> = instance.context().memory(0).view();

            for (i, v) in input.iter().enumerate() {
                s[ptr as usize + i].replace(*v);
            }

            // s[ptr as usize .. ptr as usize + len].iter().map(|x| x.get()).collect::<Vec<u8>>().copy_from_slice(input.as_ref());

            let ptr = execute.call(ptr, len as i32).unwrap();
            let s: MemoryView<u8> = instance.context().memory(0).view();

            let l = get_result(&s, ptr);
            // let cl = wasm_common_bindings::to_context_ledger(l);
        });
    }
}