extern crate common;

use common::records::Record;

#[wasmtime_rust::wasmtime]
trait WasmContract {
    fn run1(&mut self) -> String;
}

fn main() -> anyhow::Result<()> {
    let mut contract = WasmContract::load_file("contracts/target/wasm32-wasi/release/wasm_string_test.wasm")?;
    let r: Record = Record::from_base64(&contract.run1());

    println!{"{:#?}", r};

    Ok(())
}