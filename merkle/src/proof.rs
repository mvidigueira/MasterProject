use crate::node::Node;
use serde::{Serialize};

impl<K, V> Node<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    fn get_proof_internal(&self, keys: &[&K], depth: u32) -> Self {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn name() {
        unimplemented!();
    }
}