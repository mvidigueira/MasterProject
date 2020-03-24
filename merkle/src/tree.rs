use crate::node::{Leaf, Node, MerkleError, Hashable};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub struct Tree<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    root: Option<Node<K, V>>,
}

impl<K, V> Tree<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    pub fn get(&self, k: K) -> Result<&V, MerkleError> {
        match &self.root {
            None => Err(MerkleError::KeyNonExistant),
            Some(r) => r.get(k, 0),
        }
    }

    // Consider refactoring to return old value
    pub fn insert(&mut self, k: K, v: V) {
        match self.root.take() {
            None => {
                self.root = Some(Leaf::new(k, v).into());
            }
            Some(n) => {
                self.root = Some(n.insert(k, v, 0));
            }
        };
    }

    pub fn remove(&mut self, k: K) -> Option<V> {
        match self.root.take() {
            None => None,
            Some(r) => match r.remove(k, 0) {
                (v @ _, None) => v,
                (v @ _, n @ _) => {
                    self.root = n;
                    v
                }
            },
        }
    }

    pub fn get_proof(&self, k: K) -> Result<Proof<K,V>, MerkleError> {
        match &self.root {
            None => Err(MerkleError::KeyNonExistant),
            Some(r) => match r.get_proof_single(k, 0) {
                Err(r) => Err(r),
                Ok(n) => Ok(Tree{ root: Some(n) }),
            }
        }
    }

    pub fn validate(&self, proof: &Proof<K,V>) -> bool {
        match (&self.root, &proof.root) {
            (None, _) => panic!("Validating tree is empty"),
            (Some(_), None) => true,
            (Some(n), Some(p)) => n.hash() == p.hash(),
        }
    }
}

pub type Proof<K,V> = Tree<K,V>;