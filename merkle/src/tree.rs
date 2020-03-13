use super::node::Node;
use serde::ser::Serialize;
use std::borrow::Borrow;

pub struct Tree<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    root: Node<K, V>,
}

impl<K, V> Tree<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    fn _new() -> Tree<K, V> {
        unimplemented!();
    }

    fn _get<Q: ?Sized>(&self, _k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        unimplemented!();
    }

    fn _insert(&mut self, _k: K, _v: V) -> Option<V> {
        unimplemented!();
    }

    fn _remove<Q: ?Sized>(&mut self, _k: &Q) -> Option<&V> {
        unimplemented!();
    }
}
