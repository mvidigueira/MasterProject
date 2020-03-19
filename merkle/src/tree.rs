use crate::node::Node;

use serde::{Deserialize, Serialize};
use std::borrow::Borrow;

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
        Tree{ root: None }
    }

    pub fn get<Q: ?Sized>(&self, _k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        unimplemented!();
    }

    pub fn insert(&mut self, _k: K, _v: V) -> Option<V> {
        unimplemented!();
    }

    pub fn remove<Q: ?Sized>(&mut self, _k: &Q) -> Option<&V> {
        unimplemented!();
    }
}