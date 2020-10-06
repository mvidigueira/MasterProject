pub fn do_stuff() {
//     let engine = Engine::new(Config::new().wasm_multi_value(true));
//     let store = Store::new(&engine);

//     // First set up our linker which is going to be linking modules together. We
//     // want our linker to have wasi available, so we set that up here as well.

//     // Load and compile our two modules
//     let file = "contract/target/wasm32-wasi/release/contract_test.wasm";
//     let bytes = std::fs::read(file).unwrap();

//     let data = ModuleData::new(bytes.as_ref()).unwrap();

//     let b: &[u8] = bytes.as_ref();
//     let module = Module::new(&store, b).unwrap();

//     let mut imports: Vec<Extern> = Vec::new();
//     if let Some(module_name) = data.find_wasi_module_name() {
//         let wasi = Wasi::new(&store, WasiCtxBuilder::new().build().unwrap());
    
//         for i in module.imports().iter() {
//             if i.module() != module_name {
//                 panic!("unknown import module {}", i.module());
//             }
//             if let Some(export) = wasi.get_export(i.name()) {
//                 imports.push(export.clone().into());
//             } else {
//                 panic!("unknown import {}:{}", i.module(), i.name())
//             }
//         }
//     }
    
//     let instance =
//         Instance::new(&module, &imports).map_err(|t| println!("instantiation trap: {:?}", t)).unwrap();

//     let results = 
//     data
//     .invoke_export(&instance, "execute", &[])
//     .expect("wasm execution failed");

//     let s = <(String,) as wasmtime_rust::__rt::FromVecValue>::from(results)
//     .map(|t| t.0)
//     .expect("failed to convert return type");
    
//     println!("{}", s);
}

fn main() {
    // do_stuff()
}