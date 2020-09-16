// use wasm3::Environment;
// use wasm3::Module;

fn main() {
    
}

// fn main() {
//     let env = Environment::new().expect("Unable to create environment");
//     let rt = env
//         .create_runtime(1024 * 60)
//         .expect("Unable to create runtime");
    
//     let file = "../../contract_3/target/wasm32-unknown-unknown/debug/contract_test.wasm";
//     let bytes = std::fs::read(file).unwrap();

//     let module = Module::parse(&env, &bytes)
//     .expect("Unable to parse module");
    
//     let module = rt.load_module(module).expect("Unable to load module");
    
//     let allocate =
//         .find_function::<i64, i32>("execute")
//         .expect("Unable to find function");

//     let execute = module
//         .find_function::<(i32, i64), i32>("execute")
//         .expect("Unable to find function");

//     let ret = func.call(5, 2).unwrap();
//     let ret = func.call(5, 2).unwrap();

//     let mut len: [u8; 4] = [0; 4];
//     let mut pointer: [u8; 4] = [0; 4];

//     let s = unsafe {
//         rt.memory()
//     };

//     unsafe {
//         len.copy_from_slice(&(*s)[ret as usize.. ret as usize + std::mem::size_of::<i32>()]);
//         pointer.copy_from_slice(&(*s)[ret as usize + std::mem::size_of::<i32>()
//         .. ret as usize + 2*std::mem::size_of::<i32>()]);
//     };
//     let len = i32::from_be_bytes(len) as usize;
//     let pointer = i32::from_be_bytes(pointer);

//     let v: Vec<u8> = unsafe {
//         (*s)[pointer as usize .. pointer as usize + len].to_vec()
//     };

//     println!("vec is {:?}", &v);
// }