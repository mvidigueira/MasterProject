#![feature(test)]

#[cfg(test)]
mod test {
    extern crate test;
    use test::Bencher;

    use wasmtime::{Config, Engine, Store, Module, Instance, Strategy, Val};
    use wasm_common_bindings::{Ledger, ContextLedger2, get_result};

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use futures::future;
    use tokio::task;

    use std::time::{Instant};

    #[tokio::test(threaded_scheduler, core_threads = 4)]
    async fn test_full() {
        use ed25519_dalek::{Signature, Signer, Keypair};
        use rand::rngs::OsRng;

        let total = 100;

        let file = "contract_4/target/wasm32-unknown-unknown/release/contract_test_2.wasm";
        let bytes = std::fs::read(file).unwrap();
        // let module = Module::from_binary(&engine, &bytes).unwrap();
        
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

        let mut vec = vec!();

        let u: AtomicUsize = AtomicUsize::new(0);
        let u = Arc::new(u);

        let start: AtomicUsize = AtomicUsize::new(0);
        let start = Arc::new(start);
        
        for _ in 0..4 {
            let u_sync = Arc::clone(&u);
            let start_sync = Arc::clone(&start);
            let engine = Engine::new(Config::new().strategy(Strategy::Cranelift).unwrap());
            let bytes = bytes.clone();

            let input = input.clone();

            let handler = task::spawn(
                async move {
                    loop {
                        if start_sync.load(Ordering::Relaxed) > 0 {
                            break;
                        }
                    }

                    loop {
                        if u_sync.fetch_add(1, Ordering::Relaxed) < total {
                            let module = Module::from_binary(&engine, &bytes).unwrap();
                            let store = Store::new(&engine);
                            let instance = Instance::new(&store, &module, &[]).unwrap();
                            
                            let allocate = instance.get_func("allocate_vec").unwrap();
                            let execute = instance.get_func("execute").unwrap();

                            let len = input.len();

                            let ptr = allocate.call(&[wasmtime::Val::from(len as i32)]).unwrap();
                            let ptr = match ptr.get(0).unwrap() {
                                Val::I32(a) => *a,
                                _ => panic!(),
                            };
                
                            // println!("ptr: {:?}", ptr);
                
                            let mem = instance.get_memory("memory").unwrap();
                            let mem_slice = unsafe {
                                mem.data_unchecked_mut()
                            };
                
                            for (i, v) in input.iter().enumerate() {
                                mem_slice[ptr as usize + i] = *v;
                            }
                
                            let ptr = execute.call(&[wasmtime::Val::from(ptr as i32), wasmtime::Val::from(len as i32)]).unwrap();
                            let ptr = match ptr.get(0).unwrap() {
                                Val::I32(a) => *a,
                                _ => panic!(),
                            };
                
                            let mem_slice = unsafe {
                                mem.data_unchecked()
                            };
                            let l = get_result(mem_slice, ptr);
                            let _cl = wasm_common_bindings::to_context_ledger_2(l);
                        } else {
                            break;
                        }
                    }
                }
            );
            vec.push(handler);
        }


        let now = Instant::now();
        start.store(1, Ordering::Relaxed);
        future::join_all(vec).await;
        let after = Instant::now();
        println!("Total duration: {:?}", (after - now)/total as u32);
    }

    #[tokio::test]
    async fn manual_bench(/*_: &mut Bencher*/) {
        let total = 100;

        use ed25519_dalek::{Signature, Signer, Keypair};
        use rand::rngs::OsRng;

        let file = "contract_4/target/wasm32-unknown-unknown/release/contract_test_2.wasm";
        let bytes = std::fs::read(file).unwrap();
        let engine = Engine::new(Config::new().strategy(Strategy::Cranelift).unwrap());
        // let module = Module::from_binary(&engine, &bytes).unwrap();

        let now = Instant::now();
        for i in 0..total {
            let module = Module::from_binary(&engine, &bytes).unwrap();
            let store = Store::new(&engine);
            let instance = Instance::new(&store, &module, &[]).unwrap();
            
            let allocate = instance.get_func("allocate_vec").unwrap();
            let execute = instance.get_func("execute").unwrap();

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
    
            let ptr = allocate.call(&[wasmtime::Val::from(len as i32)]).unwrap();
            let ptr = match ptr.get(0).unwrap() {
                Val::I32(a) => *a,
                _ => panic!(),
            };

            // println!("ptr: {:?}", ptr);

            let mem = instance.get_memory("memory").unwrap();
            let mem_slice = unsafe {
                mem.data_unchecked_mut()
            };

            for (i, v) in input.iter().enumerate() {
                mem_slice[ptr as usize + i] = *v;
            }

            let ptr = execute.call(&[wasmtime::Val::from(ptr as i32), wasmtime::Val::from(len as i32)]).unwrap();
            let ptr = match ptr.get(0).unwrap() {
                Val::I32(a) => *a,
                _ => panic!(),
            };

            let mem_slice = unsafe {
                mem.data_unchecked()
            };
            let l = get_result(mem_slice, ptr);
            let cl = wasm_common_bindings::to_context_ledger_2(l);
        };
        let after = Instant::now();
        println!("Total duration: {:?}", (after - now)/total);

        // println!("Ledger {:?}", &cl);
    }
}