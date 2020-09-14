use merkle::error::MerkleError;
use merkle::{closest, leading_bits_in_common, Tree};

use std::borrow::Borrow;
use std::collections::VecDeque;

use drop::crypto::Digest;

use serde::Serialize;

use std::collections::HashSet;
use std::hash::Hash;
use std::sync::Arc;

use tracing::error;

use std::fmt::Debug;

pub struct HistoryTree<K, V>
where
    K: Serialize + Clone + Eq + Hash + Debug,
    V: Serialize + Clone + Eq + Debug,
{
    pub tree: Tree<K, V>,

    pub touches: VecDeque<Vec<Arc<K>>>,
    pub counts: HashSet<Arc<K>>,
    pub history: VecDeque<Digest>,
    pub history_count: usize,
    history_len: usize,

    my_d: Digest,
    pub d_list: Vec<Digest>,
}

impl<K, V> HistoryTree<K, V>
where
    K: Serialize + Clone + Eq + Hash + Debug,
    V: Serialize + Clone + Eq + Debug,
{
    pub fn new(
        history_len: usize,
        my_d: Digest,
        mut d_list: Vec<Digest>,
    ) -> Self {
        if history_len < 1 {
            panic!("history_len must be at least 1");
        }

        d_list.sort_by_key(|x| *x.as_ref());

        let mut touches = VecDeque::with_capacity(history_len + 1);
        touches.push_front(vec![]);

        Self {
            tree: Tree::new(),
            touches: touches,
            counts: HashSet::new(),
            history: VecDeque::with_capacity(history_len),
            history_count: 0,
            history_len: history_len,

            my_d: my_d,
            d_list: d_list,
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
        let d_list = &self.d_list;
        let my_d = self.my_d.as_ref();

        let is_close = move |path: [u8; 32], up_to_bit: usize| {
            let closest_d = closest(d_list, &path);
            let closest_score = std::cmp::min(
                leading_bits_in_common(closest_d.as_ref(), &path),
                up_to_bit,
            );

            std::cmp::min(leading_bits_in_common(my_d, &path), up_to_bit)
                == closest_score
        };

        let touched_records = self.touches.pop_back().unwrap();

        let last_recent_history =
            std::cmp::max(self.history_count + 1 - self.history_len, 0);
        for k in touched_records {
            if self.d_list.len() > 0 {
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

    /// "Closes" a transaction.
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
    use merkle::closest;

    use std::convert::TryFrom;
    macro_rules! h2d {
        ($data:expr) => {
            Digest::try_from($data).expect("failed to create digest")
        };
    }

    #[test]
    fn consistent_inserts_1() {
        let unused = h2d!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let mut h_tree = HistoryTree::new(10, unused, vec![]);

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
        let unused = h2d!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let mut h_tree = HistoryTree::new(10, unused, vec![]);

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
        let unused = h2d!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let mut h_tree = HistoryTree::new(10, unused, vec![]);

        h_tree.insert("Alice", 1);
        h_tree.push_history();

        let late_proof = h_tree.get_proof("Alice").unwrap();

        h_tree.remove("Alice");
        h_tree.push_history();

        assert!(!h_tree.consistent_with(&late_proof));
    }

    #[test]
    fn consistent_was_replaced_with_placeholder_1() {
        let unused = h2d!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let mut h_tree = HistoryTree::new(10, unused, vec![]);

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
        let unused = h2d!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let mut h_tree = HistoryTree::new(10, unused, vec![]);

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
        let unused = h2d!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let mut h_tree = HistoryTree::new(10, unused, vec![]);

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
        let unused = h2d!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let mut h_tree = HistoryTree::new(10, unused, vec![]);

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
        let unused = h2d!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let mut h_tree = HistoryTree::new(10, unused, vec![]);

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
        let unused = h2d!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let mut h_tree = HistoryTree::new(10, unused, vec![]);

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
        let unused = h2d!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let mut h_tree = HistoryTree::new(2, unused, vec![]);

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
    fn push_history_2() {
        let me = h2d!(
            "6F00000000000000000000000000000000000000000000000000000000000000"
        );

        let v = vec!(
            h2d!("6300000000000000000000000000000000000000000000000000000000000000"),   // L,R,R,L,L,L,R,R -> closest to Bob, Charlie
            h2d!("6F00000000000000000000000000000000000000000000000000000000000000"),   // L,R,R,L,R,R,R,R -> closest to Vanessa
            h2d!("8000000000000000000000000000000000000000000000000000000000000000"),   // R -> closest to Aaron
        );

        let mut h_tree = HistoryTree::new(2, me, v);

        h_tree.insert("Bob", 1); // L, R, ...
        h_tree.add_touch(&"Bob");
        h_tree.insert("Charlie", 2);
        h_tree.add_touch(&"Charlie");
        h_tree.push_history();

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
        let a = h2d!(
            "6300000000000000000000000000000000000000000000000000000000000000"
        );
        let b = h2d!(
            "6F00000000000000000000000000000000000000000000000000000000000000"
        );
        let c = h2d!(
            "8000000000000000000000000000000000000000000000000000000000000000"
        );

        let mut v = vec![
            a, // L,R,R,L,L,L,R,R
            b, // L,R,R,L,R,R,R,R
            c, // R
        ];

        let mut h_tree_a = HistoryTree::new(1, a, v.clone());
        let mut h_tree_b = HistoryTree::new(1, b, v.clone());
        let mut h_tree_c = HistoryTree::new(1, c, v.clone());

        let keys_existing = [
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
        ];
        for k in keys_existing.iter() {
            h_tree_a.insert(*k, 42);
            h_tree_b.insert(*k, 42);
            h_tree_c.insert(*k, 42);
        }

        h_tree_a.push_history();
        h_tree_a.push_history();
        h_tree_b.push_history();
        h_tree_b.push_history();
        h_tree_c.push_history();
        h_tree_c.push_history();

        v.sort_by_key(|x| *x.as_ref());

        let keys_searching = [
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
            "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
        ];
        for k in keys_searching.iter() {
            let d = closest(&v, drop::crypto::hash(k).unwrap().as_ref());

            let res;
            if d == &a {
                res = h_tree_a.get_proof(k);
            } else if d == &b {
                res = h_tree_b.get_proof(k);
            } else {
                res = h_tree_c.get_proof(k);
            }

            res.expect("Should have been Ok!");
        }
    }
}
