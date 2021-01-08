#![feature(test)]
#![feature(vec_into_raw_parts)]

#[cfg(test)]
mod test {
    extern crate test;
    use test::Bencher;
    
    use wasm_common_bindings::{ContextLedger, ContextLedger2, Ledger};
    // use wasmer_runtime::{imports, Func, memory::MemoryView};

    use wasmer::{Store, JIT, Module, Instance, NativeFunc, MemoryView, imports};
    use wasmer_cache::{Cache, FileSystemCache, Hash};
    use wasmer_compiler_llvm::LLVM;
    use wasmer_compiler_singlepass::Singlepass;
    use wasmer_compiler_cranelift::Cranelift;
    use wasmer_engine_native::Native;

    fn get_headless_store() -> Store {
        #[cfg(not(feature = "native"))]
        let store = Store::new(&JIT::headless().engine());

        #[cfg(feature = "native")]
        let store = Store::new(&Native::headless().engine());

        store
    }

    fn get_store() -> Store {
        // The default compiler
        let compiler = Cranelift::default();
        
        #[cfg(feature = "singlepass")]
        let compiler = Singlepass::new();
        
        #[cfg(feature = "llvm")]
        let compiler = LLVM::new();

        // The default engine
        #[cfg(not(feature = "native"))]
        let store = Store::new(&JIT::new(compiler).engine());

        #[cfg(feature = "native")]
        let store = Store::new(&Native::new(compiler).engine());

        store
    }

    fn get_result(base: &MemoryView<u8>, ptr: i32) -> Ledger {
        let base = base[..].iter().map(|x| x.get()).collect::<Vec<u8>>();
        wasm_common_bindings::get_result(&base, ptr)
    }

    #[bench]
    fn test_loaded_no_sig(b: &mut Bencher) {
        let file = "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let bytes = std::fs::read(file).unwrap();
        
        let store = get_store();
        let module = Module::new(&store, &bytes).unwrap();
        // let module = wasmer_runtime::compile_with(&bytes, &wasmer_runtime::default_compiler()).unwrap();
        b.iter(|| {
            let import_object = imports! {};
            let instance = Instance::new(&module, &import_object).unwrap();
            // let instance = module.instantiate(&import_object).unwrap();

            let allocate: NativeFunc<i32, i32> = instance.exports
            .get_native_function("allocate_vec")
            .expect("Unable to find function");

            let execute: NativeFunc<(i32, i32), i32> = instance.exports
            .get_native_function("execute")
            .expect("Unable to find function");
            
            let mut cl = ContextLedger::new();
            cl.insert("Alice".to_string(), 50);
            cl.insert("Dave".to_string(), 50);
            let l = wasm_common_bindings::to_ledger(cl);

            let args = ("Alice".to_string(), "Alice".to_string(), "Dave".to_string(), 50 as i32);
            let input = wasm_common_bindings::create_input(l, &args);
            let len = input.len();

            let ptr = allocate.call(len as i32).unwrap();
            // println!("ptr: {:?}", ptr);

            let s: MemoryView<u8> = instance.exports.get_memory("memory").unwrap().view();

            for (i, v) in input.iter().enumerate() {
                s[ptr as usize + i].replace(*v);
            }

            // s[ptr as usize .. ptr as usize + len].iter().map(|x| x.get()).collect::<Vec<u8>>().copy_from_slice(input.as_ref());

            let ptr = execute.call(ptr, len as i32).unwrap();
            let s: MemoryView<u8> = instance.exports.get_memory("memory").unwrap().view();

            let l = get_result(&s, ptr);
            // let cl = wasm_common_bindings::to_context_ledger(l);
        });
    }

    #[bench]
    fn test_loaded_with_sig(b: &mut Bencher) {
        use ed25519_dalek::{Signature, Signer, Keypair};
        use rand::rngs::OsRng;

        let file = "contract_4/target/wasm32-unknown-unknown/release/contract_test_2.wasm";
        let bytes = std::fs::read(file).unwrap();
        
        let store = get_store();
        let module = Module::new(&store, &bytes).unwrap();
        // let module = wasmer_runtime::compile_with(&bytes, &wasmer_runtime::default_compiler()).unwrap();
        b.iter(|| {
            let import_object = imports! {};
            let instance = Instance::new(&module, &import_object).unwrap();
            // let instance = module.instantiate(&import_object).unwrap();

            let allocate: NativeFunc<i32, i32> = instance.exports
            .get_native_function("allocate_vec")
            .expect("Unable to find function");

            let execute: NativeFunc<(i32, i32), i32> = instance.exports
            .get_native_function("execute")
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

            let ptr = allocate.call(len as i32).unwrap();
            // println!("ptr: {:?}", ptr);

            let s: MemoryView<u8> = instance.exports.get_memory("memory").unwrap().view();

            for (i, v) in input.iter().enumerate() {
                s[ptr as usize + i].replace(*v);
            }

            // s[ptr as usize .. ptr as usize + len].iter().map(|x| x.get()).collect::<Vec<u8>>().copy_from_slice(input.as_ref());

            let ptr = execute.call(ptr, len as i32).unwrap();
            let s: MemoryView<u8> = instance.exports.get_memory("memory").unwrap().view();

            let l = get_result(&s, ptr);
            // let cl = wasm_common_bindings::to_context_ledger(l);
        });
    }

    #[bench]
    fn test_on_file_system_cache(b: &mut Bencher) {
        let file = "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let bytes = std::fs::read(file).unwrap();

        let store = get_store();
        let module = Module::new(&store, &bytes).unwrap();

        let mut fs_cache = FileSystemCache::new("module_cache").unwrap();
        let key = Hash::new([0u8; 32]);
        fs_cache.store(key, &module).unwrap();

        // let module = wasmer_runtime::compile_with(&bytes, &wasmer_runtime::default_compiler()).unwrap();
        b.iter(|| {
            let m = unsafe {
                fs_cache.load(&store, key)
            }.unwrap();

            let import_object = imports! {};
            let instance = Instance::new(&m, &import_object).unwrap();

            let allocate: NativeFunc<i32, i32> = instance.exports
            .get_native_function("allocate_vec")
            .expect("Unable to find function");

            let execute: NativeFunc<(i32, i32), i32> = instance.exports
            .get_native_function("execute")
            .expect("Unable to find function");
            
            let mut cl = ContextLedger::new();
            cl.insert("Alice".to_string(), 50);
            cl.insert("Dave".to_string(), 50);
            let l = wasm_common_bindings::to_ledger(cl);

            let args = ("Alice".to_string(), "Alice".to_string(), "Dave".to_string(), 50 as i32);
            let input = wasm_common_bindings::create_input(l, &args);
            let len = input.len();

            let ptr = allocate.call(len as i32).unwrap();
            // println!("ptr: {:?}", ptr);

            let s: MemoryView<u8> = instance.exports.get_memory("memory").unwrap().view();

            for (i, v) in input.iter().enumerate() {
                s[ptr as usize + i].replace(*v);
            }

            // s[ptr as usize .. ptr as usize + len].iter().map(|x| x.get()).collect::<Vec<u8>>().copy_from_slice(input.as_ref());

            let ptr = execute.call(ptr, len as i32).unwrap();
            let s: MemoryView<u8> = instance.exports.get_memory("memory").unwrap().view();

            let l = get_result(&s, ptr);
            // let cl = wasm_common_bindings::to_context_ledger(l);
        });
    }

    use std::collections::HashMap;
    
    #[derive(Debug)]
    enum ModuleCacheErr {
        NotFound,
        WrongHash,
        AlreadyExistsSameHash,
        AlreadyExistsDifferentHash,
    }
    struct ModuleCache {
        map: HashMap<String, (Module, [u8; 32])>,
    }

    impl ModuleCache {
        pub fn new() -> Self {
            ModuleCache{ map: HashMap::new() }
        }

        pub fn load(&self, id: &String, hash: &[u8; 32]) -> Result<&Module, ModuleCacheErr> {
            match self.map.get(id) {
                Some((m, h)) if hash == h => Ok(m),
                None => Err(ModuleCacheErr::NotFound),
                _ => Err(ModuleCacheErr::WrongHash),
            }
        }

        pub fn store(&mut self, id: &String, hash: [u8; 32], m: Module) -> Result<(), ModuleCacheErr> {
            match self.load(id, &hash) {
                Ok(_) => Err(ModuleCacheErr::AlreadyExistsSameHash),
                Err(ModuleCacheErr::WrongHash) => Err(ModuleCacheErr::AlreadyExistsDifferentHash),
                Err(ModuleCacheErr::NotFound) => {
                    self.map.insert(id.clone(), (m, hash));
                    Ok(())
                }
                _ => unreachable!(),
            }
        }
    }

    #[bench]
    fn test_on_memory_cache(b: &mut Bencher) {
        let file = "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let bytes = std::fs::read(file).unwrap();

        let store = get_store();
        let module = Module::new(&store, &bytes).unwrap();

        let mut cache = ModuleCache::new();
        cache.store(&"Awesome".to_string(), [0;32], module).unwrap();

        // let module = wasmer_runtime::compile_with(&bytes, &wasmer_runtime::default_compiler()).unwrap();
        b.iter(|| {
            let m = cache.load(&"Awesome".to_string(), &[0;32]).unwrap();

            let import_object = imports! {};
            let instance = Instance::new(&m, &import_object).unwrap();

            let allocate: NativeFunc<i32, i32> = instance.exports
            .get_native_function("allocate_vec")
            .expect("Unable to find function");

            let execute: NativeFunc<(i32, i32), i32> = instance.exports
            .get_native_function("execute")
            .expect("Unable to find function");
            
            let mut cl = ContextLedger::new();
            cl.insert("Alice".to_string(), 50);
            cl.insert("Dave".to_string(), 50);
            let l = wasm_common_bindings::to_ledger(cl);

            let args = ("Alice".to_string(), "Alice".to_string(), "Dave".to_string(), 50 as i32);
            let input = wasm_common_bindings::create_input(l, &args);
            let len = input.len();

            let ptr = allocate.call(len as i32).unwrap();
            // println!("ptr: {:?}", ptr);

            let s: MemoryView<u8> = instance.exports.get_memory("memory").unwrap().view();

            for (i, v) in input.iter().enumerate() {
                s[ptr as usize + i].replace(*v);
            }

            // s[ptr as usize .. ptr as usize + len].iter().map(|x| x.get()).collect::<Vec<u8>>().copy_from_slice(input.as_ref());

            let ptr = execute.call(ptr, len as i32).unwrap();
            let s: MemoryView<u8> = instance.exports.get_memory("memory").unwrap().view();

            let l = get_result(&s, ptr);
            // let cl = wasm_common_bindings::to_context_ledger(l);
        });
    }
}