use super::HTree;
use merkle::MerkleError;
use drop::crypto::Digest;
use std::collections::{hash_map::Entry, HashMap};

use wasmer::{imports, Instance, Module, Store, JIT};
#[cfg(not(feature = "native"))]
use wasmer_compiler_cranelift::Cranelift;
#[cfg(feature = "llvm")]
use wasmer_compiler_llvm::LLVM;
#[cfg(feature = "singlepass")]
use wasmer_compiler_singlepass::Singlepass;
#[cfg(feature = "native")]
use wasmer_engine_native::Native;

use tracing::error;

fn get_store() -> Store {
    // The default backend
    let compiler = Cranelift::default();

    #[cfg(feature = "singlepass")]
    let compiler = Singlepass::new();

    #[cfg(feature = "llvm")]
    let compiler = LLVM::new();

    // The default compiler
    #[cfg(not(feature = "native"))]
    let store = Store::new(&JIT::new(compiler).engine());

    #[cfg(feature = "native")]
    let store = Store::new(&Native::new(compiler).engine());

    store
}

#[derive(Debug)]
pub enum ModuleCacheError {
    ModuleNotFound,
    OutdatedVersion,
    NotResponsible,
    ModuleLoadError,
    InstancingError,
}

pub struct ModuleCache {
    map: HashMap<String, (Module, Digest)>,
}

impl ModuleCache {
    pub fn new() -> Self {
        ModuleCache {
            map: HashMap::new(),
        }
    }

    pub fn get_instance(
        &mut self,
        id: &String,
        hash: &Digest,
        h_tree: &HTree,
    ) -> Result<Instance, ModuleCacheError> {
        let module = self.load(id, hash, h_tree)?;

        let import_object = imports! {};
        match Instance::new(&module, &import_object) {
            Err(e) => {
                error!("Error processing transaction: error instantiating module: {:?}", e);
                return Err(ModuleCacheError::InstancingError);
            }
            Ok(i) => Ok(i),
        }
    }

    pub fn load(
        &mut self,
        id: &String,
        hash: &Digest,
        h_tree: &HTree,
    ) -> Result<&Module, ModuleCacheError> {
        if !h_tree.covers(id) {
            return Err(ModuleCacheError::NotResponsible);
        }

        let bytes = match h_tree.get(id) {
            Err(MerkleError::KeyNonExistant) => {
                return Err(ModuleCacheError::ModuleNotFound);
            }
            Err(_) => unreachable!(),
            Ok(v) => v,
        };
        let latest_digest = drop::crypto::hash(bytes).unwrap();
        if hash != &latest_digest {
            return Err(ModuleCacheError::OutdatedVersion);
        }

        match self.map.entry(id.clone()) {
            Entry::Vacant(e) => {
                let store = get_store();
                let module = match Module::new(&store, bytes) {
                    Err(e) => {
                        error!("Error processing transaction: error loading module: {:?}", e);
                        return Err(ModuleCacheError::ModuleLoadError);
                    }
                    Ok(m) => m,
                };

                Ok(&e.insert((module, latest_digest)).0)
            }
            Entry::Occupied(mut e) => {
                if e.get().1 != latest_digest {
                    let store = get_store();
                    let module = match Module::new(&store, bytes) {
                        Err(e) => {
                            error!("Error processing transaction: error loading module: {:?}", e);
                            return Err(ModuleCacheError::ModuleLoadError);
                        }
                        Ok(m) => m,
                    };

                    e.insert((module, latest_digest));
                }

                Ok(&e.into_mut().0)
            }
        }
    }

    pub fn try_caching(
        &mut self,
        id: &String,
        h_tree: &HTree,
    ) -> Result<(), ModuleCacheError> {
        if !h_tree.covers(id) {
            return Err(ModuleCacheError::NotResponsible);
        }

        let hash = match h_tree.get(id) {
            Err(MerkleError::KeyNonExistant) => {
                return Err(ModuleCacheError::ModuleNotFound);
            }
            Err(_) => unreachable!(),
            Ok(v) => drop::crypto::hash(v).unwrap(),
        };

        self.load(id, &hash, h_tree)?;

        Ok(())
    }
}
