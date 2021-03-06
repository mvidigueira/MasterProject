#![feature(test)]
#![feature(vec_into_raw_parts)]

mod contract_simulated;

#[cfg(test)]
mod test {
    extern crate test;
    use test::Bencher;
    
    use wasm_common_bindings::{ContextLedger, ContextLedger2};

    // #[bench]
    fn test1(b: &mut Bencher) {
        use wasm3::Environment;
        use wasm3::Module;

        let file = "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let bytes = std::fs::read(file).unwrap();
    
        let env = Environment::new().expect("Unable to create environment");

        b.iter(|| {
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
                
            let len_in = 5;
            let ptr = allocate.call(len_in).unwrap();
    
            let s = unsafe {
                rt.memory_mut()
            };
    
            unsafe {
                (*s)[ptr as usize] = 69;
                (*s)[ptr as usize + len_in as usize - 1] = 72;
            }
    
            let ptr = execute.call(ptr, len_in).unwrap();
        
            let mut len: [u8; 4] = [0; 4];
            let mut pointer: [u8; 4] = [0; 4];
        
            let s = unsafe {
                rt.memory()
            };
        
            unsafe {
                len.copy_from_slice(&(*s)[ptr as usize.. ptr as usize + std::mem::size_of::<i32>()]);
                pointer.copy_from_slice(&(*s)[ptr as usize + std::mem::size_of::<i32>()
                .. ptr as usize + 2*std::mem::size_of::<i32>()]);
            };
            let len = i32::from_be_bytes(len) as usize;
            let pointer = i32::from_be_bytes(pointer);
        
            let v: Vec<u8> = unsafe {
                (*s)[pointer as usize .. pointer as usize + len].to_vec()
            };
        });
        
        // println!("vec is {:?}", &v);
    }

    #[bench]
    fn test2(b: &mut Bencher) {
        use wasm3::Environment;
        use wasm3::Module;
        
        let file = "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let bytes = std::fs::read(file).unwrap();
    
        let env = Environment::new().expect("Unable to create environment");

        // RUNTIME CREATION

        // let rt = env
        // .create_runtime(1024 * 60)
        // .expect("Unable to create runtime");

        b.iter(|| {
            // RUNTIME CREATION

            let rt = env
            .create_runtime(1024 * 60)
            .expect("Unable to create runtime");
            
            // LOADING

            let module = Module::parse(&env, &bytes)
            .expect("Unable to parse module");
            
            let module = rt.load_module(module)
            .expect("Unable to load module");

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
            let _cl = wasm_common_bindings::to_context_ledger(l);
        });
    }

    #[bench]
    fn test3(b: &mut Bencher) {
        use wasm3::Environment;
        use wasm3::Module;
        use ed25519_dalek::{Signature, Signer, Keypair};
        use rand::rngs::OsRng;
        
        let file = "contract_4/target/wasm32-unknown-unknown/release/contract_test_2.wasm";
        let bytes = std::fs::read(file).unwrap();
    
        let env = Environment::new().expect("Unable to create environment");

        b.iter(|| {
            // RUNTIME CREATION

            let rt = env
            .create_runtime(1024 * 60)
            .expect("Unable to create runtime");
            
            // LOADING

            let module = Module::parse(&env, &bytes)
            .expect("Unable to parse module");
            
            let module = rt.load_module(module)
            .expect("Unable to load module");

            // EXECUTION
            let allocate = module
                .find_function::<i32, i32>("allocate_vec")
                .expect("Unable to find function");

            let execute = module
                .find_function::<(i32, i32), i32>("execute")
                .expect("Unable to find function");
            
            let mut csprng = OsRng{};
            let kp = Keypair::generate(&mut csprng);

            let mut cl = ContextLedger2::new();
            cl.insert("Alice".to_string(), (50, (kp.public, 0)));
            cl.insert("Dave".to_string(), (50, (kp.public, 0)));
            let l = wasm_common_bindings::to_ledger_2(cl);

            let v = ("Alice".to_string(), "Dave".to_string(), 50 as i32, 0);
            let v = bincode::serialize(&v).unwrap();
            let signature: Signature = kp.sign(&v);

            let args = ("Alice".to_string(), "Dave".to_string(), 50 as i32, signature);
            let input = wasm_common_bindings::create_input(l, &args);
            let len = input.len();
            println!("{:?}", len);

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
            let cl = wasm_common_bindings::to_context_ledger_2(l);
        });
        // println!("{:?}", cl);
    }

    #[bench]
    fn test4(b: &mut Bencher) {
        use ed25519_dalek::{Signature, Signer, Keypair};
        use rand::rngs::OsRng;
        
        let file = "contract_4/target/wasm32-unknown-unknown/release/contract_test_2.wasm";
        let bytes = std::fs::read(file).unwrap();

        use crate::contract_simulated;
        let mut csprng = OsRng{};
        let kp = Keypair::generate(&mut csprng);
        let v = ("Alice".to_string(), "Dave".to_string(), 50 as i32, 0);
        let v = bincode::serialize(&v).unwrap();
        let signature: Signature = kp.sign(&v);
        
        b.iter(|| {
            let mut cl = ContextLedger2::new();
            cl.insert("Alice".to_string(), (50, (kp.public, 0)));
            cl.insert("Dave".to_string(), (50, (kp.public, 0)));
            let l = wasm_common_bindings::to_ledger_2(cl);

            let args = ("Alice".to_string(), "Dave".to_string(), 50 as i32, signature);
            let input = wasm_common_bindings::create_input(l, &args);

            let (ptr, len, _) = input.into_raw_parts();

            let l = contract_simulated::execute_sim(ptr, len as i32);

            let cl = wasm_common_bindings::to_context_ledger_2(l);
        });
        // println!("{:?}", cl);
    }
}