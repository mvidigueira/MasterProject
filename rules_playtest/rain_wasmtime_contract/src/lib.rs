#[wasmtime_rust::wasmtime]
pub trait WasmContract {
    fn execute(&mut self, records: String, args: String) -> String;
}