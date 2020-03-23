use crate::node::Node;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub struct Tree<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    root: Option<Node<K, V>>,
}

impl<K, V> Tree<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    pub fn new() -> Self {
        Tree { root: None }
    }

    pub fn get(&self, _k: K) -> Option<&V> {
        unimplemented!();
    }

    pub fn insert(&mut self, _k: K, _v: V) -> Option<V> {
        unimplemented!();
    }

    pub fn remove(&mut self, _k: K) -> Option<&V> {
        unimplemented!();
    }
}
