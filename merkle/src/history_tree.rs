use crate::node::{MerkleError};
use crate::tree::Tree;

use std::borrow::Borrow;
use std::collections::VecDeque;

use drop::crypto::Digest;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default, Eq, PartialEq, Clone, Hash)]
pub struct HistoryTree<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone + Eq,
{
    tree: Tree<K, V>,
    history: VecDeque<Digest>,
    history_count: usize,
    history_len: usize,
}

impl<K, V> HistoryTree<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone + Eq,
{

    pub fn new(history_len: usize) -> Self {
        Self { 
            tree: Tree::new(),
            history: VecDeque::with_capacity(history_len),
            history_count: 0,
            history_len: history_len,
        }
    }

    pub fn get<Q: ?Sized>(&self, k: &Q) -> Result<&V, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        self.tree.get(k)
    }

    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.tree.insert(k, v)
    }

    pub fn remove<Q: ?Sized>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        self.tree.remove(k)
    }

    pub fn get_proof<Q: ?Sized>(
        &self,
        k: &Q,
    ) -> Result<Proof<K, V>, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        self.tree.get_proof(k)
    }

    pub fn consistent_with(&self, proof: &Proof<K, V>) -> bool {
        if !self.history.contains(&proof.root_hash()) {
            return false;
        }

        for k in proof.clone_keys_to_vec().iter() {
            match self.tree.get(&k) {
                Ok(v) => {
                    if *v != *proof.get(&k).unwrap() {
                        return false;
                    }
                }
                Err(MerkleError::KeyNonExistant) => {
                    return false;
                }
                Err(MerkleError::KeyBehindPlaceholder(d)) => {
                    if !proof.get_path_digests(&k).contains(&d) {
                        return false;
                    }
                }
                Err(MerkleError::IncompatibleTrees) => unreachable!(),
            }
        }

        true
    }

    // TODO: introduce tests
    pub fn consistent_with_inserts(&self, proof: &Proof<K, V>, new_inserts: &Vec<K>) -> bool {
        if !self.history.contains(&proof.root_hash()) {
            return false;
        }

        for k in new_inserts.iter() {
            match proof.get(&k) {
                Err(MerkleError::KeyNonExistant) => (),
                _ => {
                    return false;
                },
            }

            match self.tree.get(&k) {
                Ok(_) => {
                    return false;
                }
                Err(MerkleError::KeyNonExistant) => (),
                Err(MerkleError::KeyBehindPlaceholder(d)) => {
                    if !proof.get_path_digests(&k).contains(&d) {
                        return false;
                    }
                }
                Err(MerkleError::IncompatibleTrees) => unreachable!(),
            }
        }

        true
    }

    pub fn get_validator(&self) -> Validator<K, V> {
        self.tree.get_validator()
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), MerkleError> {
        unimplemented!();
    }

    pub fn clone_to_vec(&self) -> Vec<(K, V)> {
        self.tree.clone_to_vec()
    }

    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// "Closes" a transaction.
    pub fn push_history(&mut self) {
        if self.history.len() == self.history_len {
            self.history.pop_back();
        }
        self.history.push_front(self.tree.root_hash());

        // TODO: Don't forget to replace old, non-"close" records with placeholders!
    }
}

/// A merkle proof. Used in the context of a *validating* tree (usually incomplete).
pub type Proof<K, V> = Tree<K, V>;

/// A merkle tree with only the root node (placeholder). Used as a summary of the tree.
pub type Validator<K, V> = Tree<K, V>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consistent_inserts_1() {
        let mut h_tree = HistoryTree::new(10);
    
        h_tree.insert("Alice", 1);
        h_tree.push_history();

        let late_proof = h_tree.get_proof("Alice").unwrap();

        h_tree.insert("Bob", 2);
        h_tree.push_history();

        h_tree.insert("Charlie", 3);
        h_tree.push_history();

        assert!(h_tree.consistent_with(&late_proof));
    }

    #[test]
    fn consistent_inserts_2() {
        let mut h_tree = HistoryTree::new(10);
    
        h_tree.insert("Alice", 1);
        h_tree.push_history();

        let late_proof = h_tree.get_proof("Alice").unwrap();

        h_tree.insert("Alice", 2);
        h_tree.push_history();

        assert!(!h_tree.consistent_with(&late_proof));

        h_tree.insert("Alice", 1);
        h_tree.push_history();

        assert!(h_tree.consistent_with(&late_proof));
    }

    #[test]
    fn consistent_was_removed() {
        let mut h_tree = HistoryTree::new(10);
    
        h_tree.insert("Alice", 1);
        h_tree.push_history();

        let late_proof = h_tree.get_proof("Alice").unwrap();

        h_tree.remove("Alice");
        h_tree.push_history();

        assert!(!h_tree.consistent_with(&late_proof));
    }

    #[test]
    fn consistent_was_replaced_with_placeholder_1() {
        let mut h_tree = HistoryTree::new(10);
    
        h_tree.insert("Bob", 1);
        h_tree.push_history();

        h_tree.insert("Charlie", 2);
        h_tree.push_history();

        h_tree.insert("Aaron", 3);
        h_tree.push_history();

        let proof = h_tree.get_proof("Bob").unwrap();

        // This is basically replacing ("Bob", 1) with a placeholder,
        // as if it was too far back in history and "not close":
        let mut tree = h_tree.get_proof("Charlie").unwrap();
        tree.merge(&h_tree.get_proof("Aaron").unwrap()).unwrap();
        h_tree.tree = tree;

        assert!(h_tree.consistent_with(&proof));
    }

    #[test]
    fn consistent_was_replaced_with_placeholder_2() {
        let mut h_tree = HistoryTree::new(10);
    
        h_tree.insert("Bob", 1);
        h_tree.push_history();

        h_tree.insert("Charlie", 2);
        h_tree.push_history();

        h_tree.insert("Aaron", 3);
        h_tree.push_history();

        let mut proof = h_tree.get_proof("Bob").unwrap();
        proof.merge(&h_tree.get_proof("Charlie").unwrap()).unwrap();

        // This is basically replacing ("Bob", 1) and (Charlie, 2) with a placeholder,
        // as if they are too far back in history and "not close":
        let tree = h_tree.get_proof("Aaron").unwrap();
        h_tree.tree = tree;

        assert!(h_tree.consistent_with(&proof));
    }

    #[test]
    fn consistent_new_inserts_1() {
        let mut h_tree = HistoryTree::new(10);
    
        h_tree.insert("Bob", 1);
        h_tree.push_history();

        h_tree.insert("Charlie", 2);
        h_tree.push_history();

        h_tree.insert("Aaron", 3);
        h_tree.push_history();

        let proof = h_tree.get_proof("Alice").unwrap();

        // This is replacing ("Bob", 1) and (Charlie, 2) with a placeholder,
        // as if they are too far back in history and "not close":
        let tree = h_tree.get_proof("Aaron").unwrap();
        h_tree.tree = tree;

        assert!(h_tree.consistent_with_inserts(&proof, &vec!("Alice")));
    }

    #[test]
    fn consistent_new_inserts_2() {
        let mut h_tree = HistoryTree::new(10);
    
        h_tree.insert("Bob", 1);
        h_tree.push_history();

        h_tree.insert("Charlie", 2);
        h_tree.push_history();

        h_tree.insert("Aaron", 3);
        h_tree.push_history();

        let proof = h_tree.get_proof("Alice").unwrap();

        h_tree.insert("Alice", 4);
        h_tree.push_history();

        // This is replacing ("Bob", 1), (Charlie, 2), and (Alice, 4) with a placeholder,
        // as if they are too far back in history and "not close":
        let tree = h_tree.get_proof("Aaron").unwrap();
        h_tree.tree = tree;

        assert!(!h_tree.consistent_with_inserts(&proof, &vec!("Alice")));
    }
}
