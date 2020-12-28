use merkle::error::MerkleError;
use merkle::Tree;

use std::borrow::Borrow;
use std::collections::VecDeque;

use drop::crypto::Digest;

use serde::Serialize;

use std::collections::HashSet;
use std::hash::Hash;
use std::sync::Arc;

use tracing::{error, info};

use std::fmt::Debug;
use std::num::Wrapping;

// Empty prefix includes all
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Prefix {
    key: Vec<u8>,
    remainder: u8, // total length of prefix = [key.size()-1] * 8 + remainder bits
}

impl Prefix {
    pub fn new(key: Vec<u8>, remainder: u8) -> Self {
        Prefix{key, remainder}
    }

    pub fn bit_len(&self) -> usize {
        (self.key.len()-1) * 8 + self.remainder as usize
    }

    pub fn bit(&self, n: usize) -> bool {
        if n > self.bit_len() {
            panic!("Prefix too short");
        }

        (self.key[n/8] & (1 << 7-n%8)) > 0
    }

    pub fn increment(&mut self) {
        let s = self.key.len();
        if s == 0 {
            // Cannot increment empty prefix
            return;
        }
        let increment = if self.remainder == 0 {
            1u8
        } else {
            2u8.pow(8 - self.remainder as u32)
        };

        self.key[s-1] = (Wrapping(self.key[s-1]) + Wrapping(increment)).0;

        for i in (1..s).rev() {
            if self.key[i] == 0 {
                self.key[i-1] = (Wrapping(self.key[i-1]) + Wrapping(1)).0;
            } else {
                break;
            }   
        }
    }

    pub fn set_length_in_bits(&mut self, length: usize) {
        let mut s = length / 8;
        let remainder = (length % 8) as u8;
        if remainder > 0 {
            s+=1;
        }
        self.key.resize(s, 0);
        if s > 0 && remainder > 0 {
            self.key[s-1] &= u8::MAX << (8-remainder);
        }
        self.remainder = remainder;
    }

    pub fn includes(&self, other: &Self) -> bool {
        // Compare full bytes

        let mut len_a = self.key.len() * 8;
        if self.remainder > 0 {
            len_a = len_a - 8 + self.remainder as usize;
        }

        let mut len_b = other.key.len() * 8;
        if other.remainder > 0 {
            len_b = len_b - 8 + other.remainder as usize;
        }

        let min = std::cmp::min(len_a, len_b);
        let full_byte_count = min / 8;
        let min_remainder = min % 8;

        if full_byte_count > 0 {
            match self.key[0..full_byte_count].cmp(&other.key[0..full_byte_count]) {
                std::cmp::Ordering::Equal => (),
                _ => return false,
            }
        }

        // Compare last incomplete byte
        if min_remainder > 0 {
            let (byte_a, byte_b) = (self.key[full_byte_count], other.key[full_byte_count]);
            let byte_a = (byte_a >> (8-min_remainder)) << (8-min_remainder);
            let byte_b = (byte_b >> (8-min_remainder)) << (8-min_remainder);
            match byte_a.cmp(&byte_b) {
                std::cmp::Ordering::Equal => (),
                _ => return false,
            }
        }

        return len_a <= len_b;
    }
}

pub fn set_bit(v: &mut Vec<u8>, index: usize, value: bool) {
    if value {
        let sub_index: u8 = 1 << (7 - (index % 8));
        v[(index / 8) as usize] |= sub_index;
    } else {
        let sub_index: u8 = 1 << (7 - (index % 8));
        v[(index / 8) as usize] &= !sub_index;
    }
}

impl From<&str> for Prefix {
    fn from(s: &str) -> Self {
        if s.len() > 256 {
            panic!("Prefix must have length between 0 and 256");
        }

        let mut num_bytes = s.len() / 8;
        let remainder = (s.len() % 8) as u8;
        if remainder > 0 {
            num_bytes += 1
        }

        let mut v: Vec<u8> = vec![0; num_bytes];
        for (i, c) in s.chars().enumerate() {
            if c == '0' {
                ()
            } else if c == '1' {
                set_bit(&mut v, i, true);
            } else {
                panic!("String must only contain chars 0 and 1");
            }
        }

        Prefix::new(v, remainder)
    }
}

impl Ord for Prefix {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare full bytes
        let full_byte_count = std::cmp::min(self.key.len(), other.key.len());
        if full_byte_count > 0 {
            match self.key[0..full_byte_count].cmp(&other.key[0..full_byte_count]) {
                std::cmp::Ordering::Equal => (),
                other => return other,
            }
        }

        // Compare last incomplete byte
        let min_remainder = std::cmp::min(self.remainder, other.remainder);
        if min_remainder > 0 {
            let (byte_a, byte_b) = (self.key[full_byte_count], other.key[full_byte_count]);
            let byte_a = (byte_a >> (8-min_remainder)) << (8-min_remainder);
            let byte_b = (byte_b >> (8-min_remainder)) << (8-min_remainder);
            if full_byte_count > 0 {
                match byte_a.cmp(&byte_b) {
                    std::cmp::Ordering::Equal => (),
                    other => return other,
                }
            }
        }

        // Compare bitlength
        self.remainder.cmp(&other.remainder)
    }
}

impl PartialOrd for Prefix {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub struct HistoryTree<K, V>
where
    K: Serialize + Clone + Eq + Hash + Debug,
    V: Serialize + Clone + Eq + Debug,
{
    // The Merkle tree holding the data
    pub tree: Tree<K, V>,

    // History of records touched (read or write) per operation
    // We use Arc<K> to reduce the memory usage of duplicated keys
    pub touches: VecDeque<Vec<Arc<K>>>,
    // Optimizes search for duplicate keys when pushing to the 'touches' queue
    pub counts: HashSet<Arc<K>>,

    // The root hashes corresponding to the history (evolution) of the Merkle tree
    pub history: VecDeque<Digest>,
    // The current time (= number of operations performed on the 'genesis' tree)
    pub history_count: usize,
    // The history length. How far back 'in time' we remember records not covered
    // by the prefix_list. 'Expiring' records are replaced with placeholders in the
    // tree. A history lenght of 1 is equivalent to only remembering records covered
    // by the prefix_list (only remembers the latest tree - the present).
    history_len: usize,

    // The list of prefixes covered by this tree. Records under these prefixes can
    // always be retrieved from the tree (never replaced with placeholders).
    pub prefix_list: Vec<Prefix>,
}

impl<K, V> HistoryTree<K, V>
where
    K: Serialize + Clone + Eq + Hash + Debug,
    V: Serialize + Clone + Eq + Debug,
{
    pub fn new(
        history_len: usize,
        mut prefix_list: Vec<Prefix>,
    ) -> Self {
        if history_len < 1 {
            panic!("history_len must be at least 1");
        }

        prefix_list.sort();

        let mut touches = VecDeque::with_capacity(history_len + 1);
        touches.push_front(vec![]);

        Self {
            tree: Tree::new(),
            touches: touches,
            counts: HashSet::new(),
            history: VecDeque::with_capacity(history_len),
            history_count: 0,
            history_len: history_len,

            prefix_list: prefix_list,
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
        self.tree.insert_with_count(k, v, self.history_count)
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

    pub fn get_proof_with_placeholder<Q: ?Sized>(
        &self,
        k: &Q,
    ) -> Result<Proof<K, V>, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        self.tree.get_proof_with_placeholder(k)
    }

    // unoptimized
    pub fn get_proofs<'b, II, Q: ?Sized>(
        &self,
        keys: II,
    ) -> Result<Proof<K, V>, MerkleError>
    where
        K: 'b + Borrow<Q>,
        Q: 'b + Serialize + Eq,
        II: IntoIterator<Item = &'b Q>,
    {
        let mut t = self.tree.get_validator();
        for k in keys.into_iter() {
            match self.tree.get_proof_with_placeholder(k) {
                Err(e) => return Err(e),
                Ok(p) => t.merge(&p)?,
            }
        }
        Ok(t)
    }

    pub fn consistent_with(&self, proof: &Proof<K, V>) -> bool {
        if !self.history.contains(&proof.root_hash()) {
            error!(
                "history does not contain root hash: {:?}",
                proof.root_hash()
            );
            return false;
        }

        Self::trees_are_consistent(&self.tree, &proof)
    }

    pub fn consistent_given_records(
        &self,
        proof: &Proof<K, V>,
        records: &Vec<K>,
    ) -> bool {
        if !self.history.contains(&proof.root_hash()) {
            error!(
                "history does not contain root hash: {:?}",
                proof.root_hash()
            );
            return false;
        }

        Self::trees_are_consistent_given_records(&self.tree, &proof, records)
    }

    pub fn trees_are_consistent_given_records(
        base: &Proof<K, V>,
        old: &Proof<K, V>,
        records: &Vec<K>,
    ) -> bool {
        for k in records {
            match (base.get(k), old.get(k)) {
                (Ok(v1), Ok(v2)) => {
                    if v1 != v2 {
                        error!("value of a record has changed (old might be too late)");
                        return false;
                    }
                }
                (
                    Err(MerkleError::KeyNonExistant),
                    Err(MerkleError::KeyNonExistant),
                ) => {}
                (Err(MerkleError::KeyBehindPlaceholder(d)), _) => {
                    match old.find_in_path(k, &d) {
                        Err(()) => {
                            error!("old incompatible with local stubbed node (old might be too late)");
                            return false;
                        }
                        _ => (),
                    }
                }
                (Ok(_), _) => {}
                (n1, n2) => {
                    error!("mismatch between tree nodes");
                    error!("{:?}", &n1);
                    error!("{:?}", &n2);
                    return false;
                }
            }
        }

        true
    }

    pub fn trees_are_consistent(base: &Proof<K, V>, old: &Proof<K, V>) -> bool {
        for k in old.clone_keys_to_vec().iter() {
            match base.get(k) {
                Ok(v) => {
                    if *v != *old.get(k).unwrap() {
                        error!("value of a record has changed (old might be too late)");
                        return false;
                    }
                }
                Err(MerkleError::KeyNonExistant) => {
                    error!("record no longer exists (old might be too late)");
                    return false;
                }
                Err(MerkleError::KeyBehindPlaceholder(d)) => {
                    match old.find_in_path(k, &d) {
                        Err(()) => {
                            error!("old incompatible with local stubbed node (old might be too late)");
                            return false;
                        }
                        _ => (),
                    }
                }
                Err(MerkleError::IncompatibleTrees) => unreachable!(),
            }
        }

        true
    }

    pub fn consistent_with_inserts(
        &self,
        proof: &Proof<K, V>,
        new_inserts: &Vec<&K>,
    ) -> bool {
        if !self.history.contains(&proof.root_hash()) {
            return false;
        }

        Self::trees_are_consistent_with_inserts(&self.tree, proof, new_inserts)
    }

    pub fn trees_are_consistent_with_inserts(
        base: &Proof<K, V>,
        old: &Proof<K, V>,
        new_inserts: &Vec<&K>,
    ) -> bool {
        for k in new_inserts.iter() {
            match old.get(k) {
                Err(MerkleError::KeyNonExistant) => (),
                _ => {
                    continue;
                    //return false;
                }
            }

            match base.get(k) {
                Ok(_) => {
                    return false;
                }
                Err(MerkleError::KeyNonExistant) => (),
                Err(MerkleError::KeyBehindPlaceholder(d)) => {
                    match old.find_in_path(k, &d) {
                        Err(()) => {
                            return false;
                        }
                        _ => (),
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

    pub fn add_touch(&mut self, k: &K) {
        let rc_k = Arc::new(k.clone());
        let rc_k = match self.counts.get(&rc_k) {
            None => {
                self.counts.insert(Arc::clone(&rc_k));
                rc_k
            }
            Some(rc_k) => Arc::clone(rc_k),
        };

        self.touches
            .front_mut()
            .expect("touches vec has no elements")
            .push(rc_k);
    }

    // WARNING: behaviour is unspecified if the tree is not consistent with the proof, including new_inserts.
    pub fn merge_consistent(&mut self, proof: &Tree<K, V>, records: &Vec<K>) {
        Self::merge_consistent_trees(
            &mut self.tree,
            proof,
            records,
            self.history_count,
        );

        for k in records.iter() {
            self.add_touch(k);
        }
    }

    pub fn merge_consistent_trees(
        base: &mut Tree<K, V>,
        old: &Tree<K, V>,
        records: &Vec<K>,
        count: usize,
    ) {
        for k in records {
            base.extend_knowledge(k, count, old);
        }
    }

    fn pop_touches(&mut self) {
        let prefix_list = &self.prefix_list;

        let is_close = move |path: [u8; 32], up_to_bit: usize| {
            let target = &mut Prefix::new(path.to_vec(), 0);
            target.set_length_in_bits(up_to_bit);
            // Not optimized yet
            // Binary search and comparison with left and right elements should work
            // but must verify first that it is theoretically correct
            // because is_close is true if there is p such that
            // p.includes(target) OR target.includes(p) 
            // (emphasis on the second part)
            for p in prefix_list {
                if p.includes(target) {
                    return true;
                }
                if target.includes(p) {
                    return true;
                }
            }

            return false;
        };

        let touched_records = self.touches.pop_back().unwrap();

        let last_recent_history =
            std::cmp::max(self.history_count + 1 - self.history_len, 0);
        for k in touched_records {
            if self.prefix_list.len() > 0 {
                self.tree.replace_with_placeholder(
                    k.as_ref(),
                    last_recent_history,
                    &is_close,
                );
            } else {
                self.tree.replace_with_placeholder(
                    k.as_ref(),
                    last_recent_history,
                    &|_, _| false,
                );
            }

            if Arc::strong_count(&k) == 2 {
                // this is the last reference (excluding hashset)
                self.counts.remove(&k);
            }
        }
    }

    pub fn clone_to_vec(&self) -> Vec<(K, V)> {
        self.tree.clone_to_vec()
    }

    pub fn len(&self) -> usize {
        self.tree.len()
    }

    // "Closes" a transaction.
    pub fn push_history(&mut self) {
        if self.history.len() == self.history_len {
            self.history.pop_back();
            self.pop_touches();
        }
        self.history.push_front(self.tree.root_hash());
        self.touches.push_front(vec![]);

        self.history_count += 1;
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
        let mut h_tree = HistoryTree::new(10, vec![]);

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
        let mut h_tree = HistoryTree::new(10, vec![]);

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
        let mut h_tree = HistoryTree::new(10, vec![]);

        h_tree.insert("Alice", 1);
        h_tree.push_history();

        let late_proof = h_tree.get_proof("Alice").unwrap();

        h_tree.remove("Alice");
        h_tree.push_history();

        assert!(!h_tree.consistent_with(&late_proof));
    }

    #[test]
    fn consistent_was_replaced_with_placeholder_1() {
        let mut h_tree = HistoryTree::new(10, vec![]);

        h_tree.insert("Bob", 1);
        h_tree.push_history();

        h_tree.insert("Charlie", 2);
        h_tree.push_history();

        h_tree.insert("Aaron", 3);
        h_tree.push_history();

        let proof = h_tree.get_proof("Bob").unwrap();

        // This is basically replacing ("Bob", 1) with a placeholder,
        // as if it was too far back in history and "not close":
        let tree = h_tree.get_proofs(["Charlie", "Aaron"].iter()).unwrap();
        h_tree.tree = tree;

        assert!(h_tree.consistent_with(&proof));
    }

    #[test]
    fn consistent_was_replaced_with_placeholder_2() {
        let mut h_tree = HistoryTree::new(10, vec![]);

        h_tree.insert("Bob", 1);
        h_tree.push_history();

        h_tree.insert("Charlie", 2);
        h_tree.push_history();

        h_tree.insert("Aaron", 3);
        h_tree.push_history();

        let proof = h_tree.get_proofs(["Bob", "Charlie"].iter()).unwrap();

        // This is basically replacing ("Bob", 1) and (Charlie, 2) with a placeholder,
        // as if they are too far back in history and "not close":
        let tree = h_tree.get_proof("Aaron").unwrap();
        h_tree.tree = tree;

        assert!(h_tree.consistent_with(&proof));
    }

    #[test]
    fn consistent_new_inserts_1() {
        let mut h_tree = HistoryTree::new(10, vec![]);

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

        assert!(h_tree.consistent_with_inserts(&proof, &vec!(&"Alice")));
    }

    #[test]
    fn consistent_new_inserts_2() {
        let mut h_tree = HistoryTree::new(10, vec![]);

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

        assert!(!h_tree.consistent_with_inserts(&proof, &vec!(&"Alice")));
    }

    #[test]
    fn merge_consistent_1() {
        let mut h_tree = HistoryTree::new(10, vec![]);

        h_tree.insert("Aaron", 1);
        h_tree.insert("Charlie", 2);
        h_tree.push_history();

        let late_proof =
            h_tree.get_proofs(["Aaron", "Charlie"].iter()).unwrap();

        h_tree.insert("Bob", 3);
        h_tree.insert("Alice", 4);
        h_tree.insert("Joe", 5);
        h_tree.insert("Alistair", 6);
        h_tree.push_history();

        let tree2 = h_tree
            .get_proofs(["Bob", "Alice", "Joe", "Alistair"].iter())
            .unwrap();
        h_tree.tree = tree2;

        assert!(h_tree
            .consistent_given_records(&late_proof, &vec!("Aaron", "Charlie")));

        h_tree.merge_consistent(&late_proof, &vec!["Aaron", "Charlie"]);

        assert_eq!(h_tree.get("Aaron"), Ok(&1));
        assert_eq!(h_tree.get("Charlie"), Ok(&2));
    }

    #[test]
    fn merge_consistent_new_inserts() {
        let mut h_tree = HistoryTree::new(10, vec![]);

        h_tree.insert("Bob", 1); // L, R, ...

        h_tree.push_history();

        h_tree.insert("Aaron", 2); // R, ...
        h_tree.insert("Justin", 3); // L, L,

        h_tree.push_history();

        let late_proof =
            h_tree.get_proofs(["Vanessa", "Charlie"].iter()).unwrap();

        h_tree.insert("Alice", 4);
        h_tree.insert("Joe", 5);
        h_tree.insert("Alistair", 6);

        h_tree.push_history();

        let tree2 = h_tree
            .get_proofs(["Aaron", "Justin", "Alice", "Joe", "Alistair"].iter())
            .unwrap();
        h_tree.tree = tree2;

        assert!(h_tree.consistent_with_inserts(
            &late_proof,
            &vec!(&"Vanessa", &"Charlie")
        ));
        h_tree.merge_consistent(&late_proof, &vec![&"Vanessa", &"Charlie"]);

        assert_eq!(h_tree.get("Vanessa"), Err(MerkleError::KeyNonExistant));
        assert_eq!(h_tree.get("Charlie"), Err(MerkleError::KeyNonExistant));
    }

    #[test]
    fn push_history_1() {
        let mut h_tree = HistoryTree::new(2, vec![]);

        h_tree.insert("Bob", 1); // L, R, ...
        h_tree.add_touch(&"Bob");
        h_tree.push_history();

        h_tree.insert("Aaron", 2); // R, ...
        h_tree.add_touch(&"Aaron");
        h_tree.push_history();

        h_tree.get("Bob").expect("Should be OK");
        h_tree.get("Aaron").expect("Should be OK");

        h_tree.push_history();

        h_tree.get("Bob").expect_err("Should be behind placeholder");
        h_tree.get("Aaron").expect("Should be OK");

        h_tree.push_history();

        h_tree.get("Bob").expect_err("Should be behind placeholder");
        h_tree
            .get("Aaron")
            .expect_err("Should be behind placeholder");
    }

    #[test]
    fn test_prefix() {
        print!("{}", drop::crypto::hash(&"Vanessa").unwrap());
    }

    #[test]
    fn push_history_2() {
        let mut h_tree = HistoryTree::new(2, vec!(Prefix::from("01111010")));

        h_tree.insert("Bob", 1); // L, R, ...
        h_tree.add_touch(&"Bob");
        h_tree.insert("Charlie", 2);
        h_tree.add_touch(&"Charlie");
        h_tree.push_history();

        println!("{:?}", drop::crypto::hash(&"Aaron"));

        let proof = h_tree.get_proofs(["Bob", "Charlie"].iter()).unwrap();

        h_tree.insert("Aaron", 2); // R, ...
        h_tree.add_touch(&"Aaron");
        h_tree.push_history();

        h_tree.get("Bob").expect("Should be OK");
        h_tree.get("Charlie").expect("Should be OK");
        h_tree.get("Aaron").expect("Should be OK");

        // println!("{:#?}", h_tree.tree);
        // assert!(false);

        h_tree.push_history();

        h_tree.get("Bob").expect_err("Should be behind placeholder");
        h_tree
            .get("Charlie")
            .expect_err("Should be behind placeholder");
        h_tree.get("Aaron").expect("Should be OK");

        let p = h_tree
            .get_proof("Vanessa")
            .expect("Could not get deniability proof for 'Vanessa'");
        match p.get("Vanessa") {
            Err(MerkleError::KeyNonExistant) => (),
            _ => panic!("'Vanessa' should be non existant!"),
        }

        h_tree.insert("Vanessa", 42);
        h_tree.add_touch(&"Vanessa");
        h_tree.merge_consistent(&proof, &vec!["Bob", "Charlie"]);

        h_tree.push_history();

        h_tree.get("Bob").expect("Should be OK");
        h_tree.get("Charlie").expect("Should be OK");
        h_tree.get("Vanessa").expect("Should be OK");
        println!("{:?}", h_tree.get("Aaron"));
        h_tree
            .get("Aaron")
            .expect_err("Should be behind placeholder");

        h_tree.push_history();

        h_tree.get("Bob").expect("Should be OK");
        h_tree.get("Charlie").expect("Should be OK");
        h_tree.get("Vanessa").expect("Should be OK");
        h_tree
            .get("Aaron")
            .expect_err("Should be behind placeholder");

        h_tree.push_history();

        h_tree.get("Bob").expect_err("Should be behind placeholder");
        h_tree
            .get("Charlie")
            .expect_err("Should be behind placeholder");
        h_tree.get("Vanessa").expect("Should be OK");
        h_tree
            .get("Aaron")
            .expect_err("Should be behind placeholder");
    }

    #[test]
    fn push_history_3() {
        let mut h_tree_a = HistoryTree::new(1, vec!(Prefix::from("00")));
        let mut h_tree_b = HistoryTree::new(1, vec!(Prefix::from("01")));
        let mut h_tree_c = HistoryTree::new(1, vec!(Prefix::from("1")));

        let keys_existing = [
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
        ];
        for k in keys_existing.iter() {
            h_tree_a.insert(*k, 42);
            h_tree_b.insert(*k, 42);
            h_tree_c.insert(*k, 42);
        }

        println!("Tree a: \n{:#?}\n", &h_tree_a.tree);
        println!("Tree b: \n{:#?}\n", &h_tree_b.tree);
        println!("Tree c: \n{:#?}\n", &h_tree_c.tree);

        h_tree_a.push_history();
        h_tree_a.push_history();
        h_tree_b.push_history();
        h_tree_b.push_history();
        h_tree_c.push_history();
        h_tree_c.push_history();

        println!("Tree a: \n{:#?}\n", &h_tree_a.tree);
        println!("Tree b: \n{:#?}\n", &h_tree_b.tree);
        println!("Tree c: \n{:#?}\n", &h_tree_c.tree);

        let keys_searching = [
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
            "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
        ];
        for k in keys_searching.iter() {
            let d = drop::crypto::hash(k).unwrap();
            let d_ref = d.as_ref();

            let res;
            if d_ref[0] < 64u8 {
                res = h_tree_a.get_proof(k);
            } else if d_ref[0] >= 64u8 && d_ref[0] < 128u8 {
                res = h_tree_b.get_proof(k);
            } else {
                res = h_tree_c.get_proof(k);
            }

            res.expect("Should have been Ok!");
        }
    }

    // #[test]
    // fn test_prefixes() {
    //     let target = Prefix::from("1");
    //     let p = Prefix::from("01111010");
    //     println!("P: {:?}, Target: {:?}, Is_close: {}", p, target, target.includes(&p) || p.includes(&target));
    // }
}
