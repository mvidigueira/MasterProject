#![feature(test)]
#![feature(vec_into_raw_parts)]

#[cfg(test)]
mod test {
    extern crate test;
    use test::Bencher;

    // #[bench]
    // fn test(b: &mut Bencher) {
    //     use wasmtime::*;
    //     use wasmtime_wasi::{Wasi, WasiCtx};

    //     let engine = Engine::default();
    //     let store = Store::new(&engine);
    //     let mut linker = Linker::new(&store);
    
    //     // Create an instance of `Wasi` which contains a `WasiCtx`. Note that
    //     // `WasiCtx` provides a number of ways to configure what the target program
    //     // will have access to.
    //     // let wasi = Wasi::new(&store, WasiCtx::new(std::env::args()).unwrap());
    //     // wasi.add_to_linker(&mut linker).unwrap();
    
    //     // Instantiate our module with the imports we've created, and run it.
    //     let file = "contract/target/wasm32-unknown-unknown/release/contract_test.wasm";
    //     let bytes = std::fs::read(file).unwrap();

    //     let module = Module::from_binary(store.engine(), &bytes).unwrap();
    //     let instance: wasmtime::Instance = linker.instantiate(&module).unwrap();

    //     // let v: Vec<u8> = vec!();
    //     // b.iter(|| {
    //     //     instance.get_func("execute").unwrap().call(&[Val::I32(v.as_mut_ptr())]).unwrap();
    //     // })
    // }

    #[bench]
    fn test2(b: &mut Bencher) {
        use wasm3::Environment;
        use wasm3::Module;

        let env = Environment::new().expect("Unable to create environment");
        let rt = env
            .create_runtime(1024 * 60)
            .expect("Unable to create runtime");
        
        let file = "contract_3/target/wasm32-unknown-unknown/debug/contract_test.wasm";
        let bytes = std::fs::read(file).unwrap();

        b.iter(|| {
            let module = Module::parse(&env, &bytes)
            .expect("Unable to parse module");
    
            let module = rt.load_module(module).expect("Unable to load module");
            
            let func = module
                .find_function::<(i64, i64), i32>("add")
                .expect("Unable to find function");

            func.call(3, 6).unwrap()
        })

        // println!("Wasm says that 3 + 6 is {}", func.call(3, 6).unwrap())
    }

    #[test]
    fn test3() {
        use wasm3::Environment;
        use wasm3::Module;

        let env = Environment::new().expect("Unable to create environment");
        let rt = env
            .create_runtime(1024 * 60)
            .expect("Unable to create runtime");
        
        let file = "contract_3/target/wasm32-unknown-unknown/debug/contract_test.wasm";
        let bytes = std::fs::read(file).unwrap();
    
        let module = Module::parse(&env, &bytes)
        .expect("Unable to parse module");
        
        let module = rt.load_module(module).expect("Unable to load module");

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
    
        println!("vec is {:?}", &v);
    }

    fn make_vec(len: usize, pointer: *mut u8) -> Vec<u8> {
        [len.to_be_bytes(), (pointer as usize).to_be_bytes()].concat()
    }

    #[test]
    fn name() {
        println!("{:?}", make_vec(1, &mut 5));
        println!("{:?}", make_vec(1, &mut 5).len());
        println!("{:?}", std::mem::size_of::<usize>());
    }
}