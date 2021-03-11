use crate::node::{Hashable, MerkleError, Node, Placeholder};

use std::borrow::Borrow;

use drop::crypto::Digest;

use serde::{Deserialize, Serialize, Deserializer};

/// A merkle tree supporting both existence and deniability proofs.
///
/// Due to the way key-value pairs are stored in the merkle tree, there is a one-to-one
/// mapping between any set of key-value pairs and a merkle tree. This permits the
/// creation of deniability proofs, i.e. proofs that show that a key-value pair with a
/// specific key doesn't (yet) exist. Please refer to the end of this documentation for
/// a brief explanation.
///
/// Note that this is unlike normal merkle trees following the [RFC6962](https://tools.ietf.org/html/rfc6962)
/// standard which are generally balanced, and for whi
/// ch the order of key-value pairs
/// in the tree is determined by the order of insertion.
///
/// The default hashing algorithm is currently SHA256 (see [`hash`]), though this
/// is subject to change at any point in the future.
///
/// It is required that the keys implement the [`Eq`], [`Serialize`], and [`Clone`]
/// traits, although this can frequently be achieved by using
/// `#[derive(PartialEq, Eq, Serialize, Clone)]`.
/// If you implement these yourself, it is important that the following
/// property holds:
///
/// ```text
/// k1 == k2 -> hash(k1) == hash(k2)
/// ```
///
/// In other words, if two keys are equal, their hashes must be equal.
///
/// It is a logic error for a key to be modified in such a way that the key's
/// hash, as determined by the [`hash`] function, or its equality,
/// as determined by the [`Eq`] trait, changes while it is in the tree. This
/// is normally only possible through [`Cell`], [`RefCell`], global state, I/O,
/// or unsafe code.
///
/// Values must also implement the [`Serialize`] and [`Clone`] traits, as trees
/// are designed to be sent over the network.
///
/// Currently, due to the way proofs are constructed independently from the
/// generating tree, both keys and values must implement the [`Clone`] trait.
/// This might be subject to change in the future.
///
/// # Examples
///
/// ```
/// extern crate merkle;
/// use merkle::Tree;
///
/// // Type inference lets us omit an explicit type signature (which
/// // would be `Tree<String, String>` in this example).
/// let mut color_preferences = Tree::new();
///
/// // Add some preferences.
/// color_preferences.insert(
///     "Alice".to_string(),
///     "red".to_string(),
/// );
/// color_preferences.insert(
///     "Bob".to_string(),
///     "green".to_string(),
/// );
/// color_preferences.insert(
///     "Charlie".to_string(),
///     "blue".to_string(),
/// );
///
/// // Bob wants to remove his preference.
/// // When trees store owned values (String), they can still be
/// // queried using references (&str).
/// let old_preference = color_preferences.remove("Bob");
/// assert_eq!(old_preference.unwrap(), "green");
///
/// // Charlie actually preferes 'cyan'. Let's change his preference.
/// let old_preference = color_preferences.insert(
///     "Charlie".to_string(),
///     "cyan".to_string(),
/// );
/// assert_eq!(old_preference.unwrap(), "blue");
///
/// // Let's get a cryptographic proof of Alice's preference.
/// let proof = color_preferences.get_proof("Alice").unwrap();
///
/// // We can check that it's valid.
/// assert!(color_preferences.validate(&proof));
///
/// // And we can get the corresponding value.
/// assert_eq!(proof.get("Alice").unwrap(), "red");
/// ```
///
/// The easiest way to use `Tree` with a custom key type is to
/// derive [`Eq`], [`Serialize`], and [`Clone`], and the same for a custom
/// value type with [`Serialize`] and [`Clone`].
///
/// [`Eq`]: https://doc.rust-lang.org/std/cmp/trait.Eq.html
/// [`Serialize`]: https://docs.serde.rs/serde/trait.Serialize.html
/// [`Deserialize`]: https://docs.serde.rs/serde/trait.Deserialize.html
/// [`Clone`]: https://doc.rust-lang.org/std/clone/trait.Clone.html
/// [`RefCell`]: https://doc.rust-lang.org/std/cell/struct.RefCell.html
/// [`Cell`]: https://doc.rust-lang.org/std/cell/struct.Cell.html
/// [`hash`]: ../drop/crypto/hash/fn.hash.html
///
/// # Caching and Hash recomputation
/// 
/// For trees with large numbers of records, computing the root hash from
/// scratch after every modification can be very costly.
/// 
/// To avoid unnecessary recomputation after each modification, each
/// internal node in a tree caches its digest. This digest is only 
/// updated on an as-needed basis, e.g. when the node lies along the path
/// of a modification, such as an insertion or removal.
/// 
/// It is important to note that all cached values in a tree are skipped
/// on serialization ([`Serialize`]) and recomputed on deserialization
/// ([`Deserialize`]), thus ensuring that they are locally valid at all
/// times, in spite of any prior malicious tampering that might have happened.
/// 
/// # One-to-one mapping of key-value pairs.
///
/// Key-Value pairs are placed in the tree along the path corresponding to the hash of their keys.
/// E.g. {Key: "Alice", Value: 3} -> hash("Alice")
/// -> b00100110... -> Left (0), Left (0), Right (1), Left (0)...
///
/// Any two keys (e.g. k1, k2) with respective hashes having the first
/// N bits in common (i.e. hash(k1)[bit0..bitN] == hash(k1)[bit0..bitN]), will share
/// the same branch/path in the tree until depth N.
///
/// By proving that some other key-value pair is present along the path of the our key, we prove
/// that that key is not present in the tree; if it was, then the branch would run deeper until it
/// forked and we found our key.
///
/// E.g.:
/// ```text
/// hash(k1) = b000..
/// hash(k2) = b110..
/// hash(k3) = b111..
/// ```
///
/// Tree without k3:
/// ```text
///         o
///        / \
///      k1   k2
/// ```
/// Tree after k3 is inserted:
/// ```text
///         o
///        / \
///      k1   o
///            \
///             o
///            / \
///          k2   k3
/// ```

use serde::de;

#[derive(Debug, Serialize, Default, Eq, PartialEq, Clone, Hash)]
pub struct Tree<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    root: Node<K, V>,
}

// Special trick to have serde deserialize call a finalize hook at the end.
// This is necessary to correctly set the cached digests (update_cache_recursive).
impl<'de, K, V> Deserialize<'de> for Tree<K, V>
where
    K: Serialize + Clone + Eq + Deserialize<'de>,
    V: Serialize + Clone + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Debug, Serialize, Deserialize, Default)]
        struct TreeDeser<K,V>
        where
            K: Serialize + Clone + Eq,
            V: Serialize + Clone,
        {
            root: Node<K, V>,
        }

        match TreeDeser::deserialize(deserializer) {
            Err(e) => Err(e),
            Ok(mut td) => {
                if !td.root.has_valid_key_positions() {
                    return Err(de::Error::custom("tree leaves do not obey hash position requirements"));
                }
                td.root.update_cache_recursive();
                Ok(Tree{ root: td.root })
            }
        }
    }
}

impl<K, V> Tree<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    /// Creates an empty `Tree`
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate merkle;
    /// use merkle::Tree;
    ///
    /// let mut tree: Tree<&str, i32> = Tree::new();
    /// ```
    pub fn new() -> Self {
        Tree { root: Node::default() }
    }

    /// Returns a reference to the value corresponding to the key.
    ///
    /// The key may be any borrowed form of the tree's key type, but
    /// [`Serialize`] and [`Eq`] on the borrowed form *must* match those for
    /// the key type.
    ///
    /// [`Eq`]: https://doc.rust-lang.org/std/cmp/trait.Eq.html
    /// [`Serialize`]: https://docs.serde.rs/serde/trait.Serialize.html
    ///
    /// # Errors
    /// If the tree did not have the key present and it is guaranteed to not exist,
    /// [`KeyNonExistant`] is returned.
    ///
    /// If the tree did not have the key present but it cannot determine if it does or does not exist
    /// (e.g. locally part of the tree is missing, replaced by a placeholder), [`KeyBehindPlaceholder`] is returned.
    ///
    /// [`KeyNonExistant`]: error/enum.MerkleError.html
    /// [`KeyBehindPlaceholder`]: error/enum.MerkleError.html
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate merkle;
    /// use merkle::Tree;
    /// use merkle::MerkleError::KeyNonExistant;
    ///
    /// let mut tree = Tree::new();
    /// tree.insert(1, "a");
    /// assert_eq!(tree.get(&1), Ok(&"a"));
    /// assert_eq!(tree.get(&2), Err(KeyNonExistant));
    /// ```
    pub fn get<Q: ?Sized>(&self, k: &Q) -> Result<&V, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        self.root.get(k, 0)
    }

    /// Inserts a key-value pair into the tree.
    ///
    /// If the tree did not have this key present, [`None`] is returned.
    ///
    /// If the tree did have this key present, the value is updated, and the old value is returned.
    /// The key is not updated, though; this matters for types that can be `==` without being identical.
    ///
    /// [`None`]: https://doc.rust-lang.org/std/option/enum.Option.html#variant.None
    ///
    /// # Panics
    ///
    /// If the tree is using placeholders (such as a tree generated by [`get_proof`]),
    /// it will panic if there is a placeholder in the path to the key.
    ///
    /// [`get_proof`]: #method.get_proof
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate merkle;
    /// use merkle::Tree;
    ///
    /// let mut tree = Tree::new();
    /// assert_eq!(tree.insert("Alice", 1), None);
    ///
    /// tree.insert("Alice", 2);
    /// assert_eq!(tree.insert("Alice", 3), Some(2));
    /// assert_eq!(tree.get("Alice"), Ok(&3));
    /// ```
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.insert_with_count(k, v, 0)
    }

    /// Removes a key from the tree, returning the value at the key if the
    /// key was previously in the tree.
    ///
    /// The key may be any borrowed form of the tree's key type, but
    /// [`Serialize`] and [`Eq`] on the borrowed form *must* match those for
    /// the key type.
    ///
    /// [`Eq`]: https://doc.rust-lang.org/std/cmp/trait.Eq.html
    /// [`Serialize`]: https://docs.serde.rs/serde/trait.Serialize.html
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate merkle;
    /// use merkle::Tree;
    ///
    /// let mut tree = Tree::new();
    /// tree.insert(1, "a");
    /// assert_eq!(tree.remove(&1), Some("a"));
    /// assert_eq!(tree.remove(&1), None);
    /// ```
    pub fn remove<Q: ?Sized>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        let mut n = Node::default();
        std::mem::swap(&mut n, &mut self.root);

        let (v, n) = n.remove(k, 0, 0);
        self.root = n;
        v
    }

    /// Returns a proof that the key is or is not present in the tree.
    ///
    /// The key may be any borrowed form of the tree's key type, but
    /// [`Serialize`] and [`Eq`] on the borrowed form *must* match those for
    /// the key type.
    ///
    /// [`Eq`]: https://doc.rust-lang.org/std/cmp/trait.Eq.html
    /// [`Serialize`]: https://docs.serde.rs/serde/trait.Serialize.html
    /// 
    /// # Errors
    /// If the tree cannot determine if the key does or does not exist
    /// (e.g. locally part of the tree is missing, replaced by a placeholder), [`KeyBehindPlaceholder`] is returned.
    ///
    /// [`KeyBehindPlaceholder`]: error/enum.MerkleError.html
    /// # Examples
    ///
    /// ```
    /// extern crate merkle;
    /// use merkle::Tree;
    /// use merkle::MerkleError::{KeyBehindPlaceholder, KeyNonExistant};
    ///
    /// let mut tree = Tree::new();
    /// tree.insert(1, "a");
    /// tree.insert(2, "b");
    ///
    /// let proof = tree.get_proof(&1).unwrap();    // Existence proof
    /// assert!(tree.validate(&proof));
    /// assert_eq!(proof.get(&1), Ok(&"a"));
    /// match proof.get(&2) {
    ///     Err(KeyBehindPlaceholder(_)) => (),
    ///     _ => unreachable!(),
    /// }
    ///
    /// let proof = tree.get_proof(&3).unwrap();    // Deniability proof (non-existence)
    /// assert!(tree.validate(&proof));
    /// assert_eq!(proof.get(&3), Err(KeyNonExistant));
    /// ```
    pub fn get_proof<Q: ?Sized>(
        &self,
        k: &Q,
    ) -> Result<Proof<K, V>, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        match self.root.get_proof_single(k, 0) {
            Err(r) => Err(r),
            Ok(n) => Ok(Tree { root: n }),
        }
    }

    /// Returns `true` if the given proof/tree is valid (its associations are valid),
    /// from the point of view of this tree.
    ///
    /// Outdated proofs (compared to the tree) are considered invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate merkle;
    /// use merkle::Tree;
    ///
    /// let mut tree = Tree::new();
    /// tree.insert(1, "a");
    ///
    /// let proof = tree.get_proof(&1).unwrap();    // Existence proof
    /// assert!(tree.validate(&proof));
    ///
    /// let proof = tree.get_proof(&3).unwrap();    // Deniability proof (non-existence)
    /// assert!(tree.validate(&proof));             // Still a valid proof
    /// ```
    pub fn validate(&self, proof: &Proof<K, V>) -> bool {
        self.root.hash() == proof.root.hash()
    }

    /// Returns a "validator": a new tree with a single (placeholder) node compatible with
    /// the previous tree (i.e. with the same hash).
    ///
    /// The validator can be used to validate proofs instead of the original tree.
    ///
    /// The validator is independent from the tree; generally, it will not accept proofs
    /// obtained on newer versions of the original tree, unless the new version is equivalent
    /// to the old one, or on the unlikely event that there is a hash collision.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate merkle;
    /// use merkle::Tree;
    ///
    /// let mut tree = Tree::new();
    /// tree.insert(1, "a");
    /// tree.insert(2, "b");
    ///
    /// let validator = tree.get_validator();
    ///
    /// let proof = tree.get_proof(&1).unwrap();
    /// assert_eq!(true, tree.validate(&proof));
    /// assert_eq!(true, validator.validate(&proof));
    ///
    /// tree.remove(&2);
    /// let more_recent_proof = tree.get_proof(&1).unwrap();
    /// assert_eq!(true, tree.validate(&more_recent_proof));
    /// assert_eq!(false, validator.validate(&more_recent_proof));
    /// ```
    pub fn get_validator(&self) -> Validator<K, V> {
        Tree{ root: Placeholder::new(self.root.hash()).into() }
    }

    /// Returns the `Digest` corresponding to the root of the Tree.
    pub fn root_hash(&self) -> Digest {
        self.root.hash()
    }

    /// Merges two *compatible* trees, modifying the first.
    /// 
    /// Concretely, it replaces placeholders in the first tree with the concrete sub-trees
    /// in the second tree. The first tree is therefore extended with the missing information
    /// (key-value associations) that the second tree possesses.
    ///
    /// This can be used as a method to merge (and condense) multiple proofs into one.
    ///
    /// # Errors
    /// If the trees are not compatible, [`IncompatibleTrees`] is returned.
    ///
    /// [`IncompatibleTrees`]: error/enum.MerkleError.html
    /// 
    /// # Examples
    ///
    /// ```
    /// extern crate merkle;
    /// use merkle::Tree;
    ///
    /// let mut tree = Tree::new();
    /// tree.insert(1, "a");
    /// tree.insert(2, "b");
    ///
    /// let proof1 = tree.get_proof(&1).unwrap();
    /// let proof2 = tree.get_proof(&2).unwrap();
    /// 
    /// let mut validator = tree.get_validator();
    ///
    /// validator.merge(&proof1);
    /// validator.merge(&proof2);
    /// 
    /// assert_eq!(validator.get(&1), Ok(&"a"));
    /// assert_eq!(validator.get(&2), Ok(&"b"));
    /// ```
    pub fn merge(&mut self, other: &Self) -> Result<(), MerkleError> {
        if self.root.hash() != other.root.hash() {
            return Err(MerkleError::IncompatibleTrees);
        }

        match (&mut self.root, &other.root) {
            (Node::Placeholder(_), Node::Placeholder(_)) => (),
            (Node::Placeholder(_), n) => {
                self.root = n.clone();
            },
            (a, b) => {
                a.merge_unchecked(&b);
            },
        }

        Ok(())
    }

    /// Copies the tree's key-value pairs, returning a vector.
    /// 
    /// The key-value pairs are inserted by increasing order of the hashes of the keys, as per [`hash`].
    ///
    /// [`hash`]: ../drop/crypto/hash/fn.hash.html
    /// 
    /// # Examples
    ///
    /// ```
    /// extern crate merkle;
    /// use merkle::Tree;
    ///
    /// let mut tree = Tree::new();
    /// tree.insert(1, "a");
    /// tree.insert(2, "b");
    /// 
    /// let v = tree.clone_to_vec();
    /// 
    /// assert!(v.contains(&(1, "a")));
    /// assert!(v.contains(&(2, "b")));
    /// ```
    pub fn clone_to_vec(&self) -> Vec<(K, V)> {
        let mut vec = Vec::new();
        self.root.collect(&mut vec);
        vec
    }

    /// Copies the tree's keys, returning a vector.
    /// 
    /// The keys pairs are inserted by increasing order of the hashes of the keys, as per [`hash`].
    ///
    /// [`hash`]: ../drop/crypto/hash/fn.hash.html
    /// 
    /// # Examples
    ///
    /// ```
    /// extern crate merkle;
    /// use merkle::Tree;
    ///
    /// let mut tree = Tree::new();
    /// tree.insert(1, "a");
    /// tree.insert(2, "b");
    /// 
    /// let keys = tree.clone_keys_to_vec();
    /// 
    /// assert!(keys.contains(&1));
    /// assert!(keys.contains(&2));
    /// ```
    pub fn clone_keys_to_vec(&self) -> Vec<K> {
        let mut vec = Vec::new();
        self.root.collect_keys(&mut vec);
        vec
    }


    /// Returns the number of elements in the tree, also referred to as its 'length'.
    /// 
    /// # Examples
    ///
    /// ```
    /// extern crate merkle;
    /// use merkle::Tree;
    ///
    /// let mut tree = Tree::new();
    /// tree.insert(1, "a");
    /// tree.insert(2, "b");
    /// 
    /// assert_eq!(tree.len(), 2);
    /// ```
    pub fn len(&self) -> usize {
        self.root.len()
    }

    pub fn find_in_path<Q: ?Sized>(&self, k: &Q, d: &Digest) -> Result<&Node<K, V>, ()>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        self.root.find_in_path(k, d, 0)
    }

    // Behaviour is unspecified if the tree is not consistent with proof
    pub fn extend_knowledge<Q: ?Sized>(&mut self, k: &Q, new_count: usize, proof: &Tree<K, V>)
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        let mut n = Node::default();
        std::mem::swap(&mut n, &mut self.root);

        self.root = n.extend_knowledge(k, new_count, &proof.root, 0)
    }

    pub fn insert_with_count(&mut self, k: K, v: V, count: usize) -> Option<V> {
        let mut n = Node::default();
        std::mem::swap(&mut n, &mut self.root);

        let (v, n) = n.insert(k, v, count, 0);
        self.root = n;
        v
    }

    pub fn replace_with_placeholder<Q: ?Sized, F>(
        &mut self,
        k: &Q,
        min_count: usize,
        is_close: &F)
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
        F: Fn([u8; 32], usize) -> bool,
    {
        let mut n = Node::default();
        std::mem::swap(&mut n, &mut self.root);

        self.root = n.replace_with_placeholder(k, min_count, is_close, 0);
    }

    pub fn get_proof_with_placeholder<Q: ?Sized>(
        &self,
        k: &Q,
    ) -> Result<Proof<K, V>, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        match self.root.get_proof_single_with_placeholder(k, 0) {
            Err(r) => Err(r),
            Ok(n) => Ok(Tree { root: n }),
        }
    }
}

/// A merkle proof. Used in the context of a *validating* tree (usually incomplete).
pub type Proof<K, V> = Tree<K, V>;

/// A merkle tree with only the root node (placeholder). Used as a summary of the tree.
pub type Validator<K, V> = Tree<K, V>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MerkleError::{KeyBehindPlaceholder, KeyNonExistant, IncompatibleTrees};

    #[test]
    fn get1() {
        let mut tree = Tree::new();
        tree.insert(1, "a");

        assert_eq!(tree.get(&1), Ok(&"a"));
    }

    #[test]
    fn get_err_non_existant() {
        let mut tree = Tree::new();
        tree.insert(1, "a");

        assert_eq!(tree.get(&2), Err(KeyNonExistant));
    }

    macro_rules! assert_behind_ph {
        ($data:expr) => {
            match $data {
                Err(KeyBehindPlaceholder(_)) => (),
                _ => panic!("key should be behind placeholder"),
            }
        };
    }

    #[test]
    fn get_err() {
        let mut tree = Tree::new();
        tree.insert("Aaron", 1);
        tree.insert("Bob", 1);
        let proof = tree.get_proof("Aaron").unwrap();

        assert_behind_ph!(proof.get("Bob"));
    }

    #[test]
    fn insert1() {
        let mut tree = Tree::new();
        assert_eq!(tree.insert("Alice", 1), None);

        tree.insert("Alice", 2);
        assert_eq!(tree.insert("Alice", 3), Some(2));
        assert_eq!(tree.get("Alice"), Ok(&3));
    }

    #[test]
    fn remove1() {
        let mut tree = Tree::new();
        tree.insert("Alice", 1);
        assert_eq!(tree.get("Alice"), Ok(&1));

        assert_eq!(tree.remove("Alice"), Some(1));
        assert_eq!(tree.get("Alice"), Err(KeyNonExistant));

        assert_eq!(tree.remove("Alice"), None);
    }

    #[test]
    fn get_proof1() {
        let mut tree = Tree::new();
        tree.insert("Aaron", 1);
        tree.insert("Bob", 2);
        tree.insert("Charlie", 3);

        let proof = tree.get_proof("Bob").unwrap();
        assert_eq!(proof.get("Bob"), Ok(&2));
        assert_behind_ph!(proof.get("Aaron"));
        assert_behind_ph!(proof.get("Charlie"));
    }

    #[test]
    fn get_proof2() {
        let mut tree = Tree::new();
        tree.insert("Aaron", 1);
        tree.insert("Bob", 2);
        tree.insert("Charlie", 3);

        let proof = tree.get_proof("Alice").unwrap();

        assert_eq!(proof.get("Alice"), Err(KeyNonExistant));
    }

    #[test]
    fn get_proof_err_behind_placeholder() {
        let mut tree = Tree::new();
        tree.insert("Aaron", 1); // R
        tree.insert("Bob", 2); // L,...
        tree.insert("Charlie", 3); // L,...

        let proof = tree.get_proof("Charlie").unwrap();

        assert_behind_ph!(proof.get("Aaron"));
    }

    #[test]
    fn validate1() {
        let mut tree = Tree::new();
        tree.insert("Aaron", 1); // R
        tree.insert("Bob", 2); // L,...
        tree.insert("Charlie", 3); // L,...

        let proof = tree.get_proof("Charlie").unwrap();
        assert!(tree.validate(&proof));
    }

    #[test]
    fn validate2() {
        let mut tree = Tree::new();
        tree.insert("Aaron", 1); // R
        tree.insert("Bob", 2); // L,...
        tree.insert("Charlie", 3); // L,...

        let proof = tree.get_proof("Charlie").unwrap();

        tree.insert("Natalie", 4);

        assert!(!tree.validate(&proof));
    }

    #[test]
    fn validate_ser_de() {
        let mut tree = Tree::new();
        tree.insert("Aaron", 1); // R
        tree.insert("Bob", 2); // L,...
        tree.insert("Charlie", 3); // L,...

        let proof = tree.get_proof("Charlie").unwrap();
        
        extern crate bincode;

        let ser = bincode::serialize(&proof).unwrap();
        let proof: Proof<_,_> = bincode::deserialize(&ser).unwrap();

        assert!(tree.validate(&proof));
    }

    #[test]
    fn get_validator1() {
        let mut tree = Tree::new();
        tree.insert(1, "a");
        tree.insert(2, "b");

        let validator = tree.get_validator();

        let proof = tree.get_proof(&1).unwrap();
        assert_eq!(true, tree.validate(&proof));
        assert_eq!(true, validator.validate(&proof));

        tree.remove(&1);
        let more_recent_proof = tree.get_proof(&2).unwrap();
        assert_eq!(true, tree.validate(&more_recent_proof));
        assert_eq!(false, validator.validate(&more_recent_proof));
    }

    #[test]
    fn merge() {
        let mut tree = Tree::new();
        tree.insert(1, "a");
        tree.insert(2, "b");
    
        let proof1 = tree.get_proof(&1).unwrap();
        let proof2 = tree.get_proof(&2).unwrap();
    
        let mut validator = tree.get_validator();
    
        assert_eq!(validator.merge(&proof1), Ok(()));
        assert_eq!(validator.merge(&proof2), Ok(()));
    
        assert_eq!(validator.get(&1), Ok(&"a"));
        assert_eq!(validator.get(&2), Ok(&"b"));
    }

    #[test]
    fn merge_err() {
        let mut tree = Tree::new();
        
        tree.insert(1, "a");
        let proof1 = tree.get_proof(&1).unwrap();

        tree.insert(2, "b");
        let proof2 = tree.get_proof(&2).unwrap();
    
        let mut validator = tree.get_validator();
    
        assert_eq!(validator.merge(&proof1), Err(IncompatibleTrees));
        assert_eq!(validator.merge(&proof2), Ok(()));
    }
}
