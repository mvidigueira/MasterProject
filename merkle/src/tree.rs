use crate::node::{Hashable, Leaf, MerkleError, Node};
use std::borrow::Borrow;

use serde::{Deserialize, Serialize};

/// A merkle tree supporting both existence and deniability proofs.
///
/// Due to the way key-value pairs are stored in the merkle tree, there is a one-to-one
/// mapping between any set of key-value pairs and a merkle tree. This permits the
/// creation of deniability proofs, i.e. proofs that show that a key-value pair with a
/// specific key doesn't (yet) exist. Please refer to the end of this documentation for
/// a brief explanation.
/// 
/// Note that this is unlike normal merkle trees following the [RFC6962](https://tools.ietf.org/html/rfc6962)
/// standard which are generally balanced, and for which the order of key-value pairs
/// in the tree is determined by the order of insertion.
///
/// The default hashing algorithm is currently SHA256, though this is
/// subject to change at any point in the future.
///
/// It is required that the keys implement the [`Eq`], [`Serialize`], and [`Clone`] 
/// traits, although this can frequently be achieved by using 
/// `#[derive(PartialEq, Eq, Serialize, Clone)]`.
/// If you implement these yourself, it is important that the following
/// property holds:
///
/// ```text
/// k1 == k2 -> k1.serialize(S) == k2.serialize(S)
/// ```
///
/// In other words, if two keys are equal, their serialization must be equal.
///
/// It is a logic error for a key to be modified in such a way that the key's
/// serialization, as determined by the [`Serialize`] trait, or its equality,
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
/// [`Clone`]: https://doc.rust-lang.org/std/clone/trait.Clone.html
/// [`RefCell`]: https://doc.rust-lang.org/std/cell/struct.RefCell.html
/// [`Cell`]: https://doc.rust-lang.org/std/cell/struct.Cell.html
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

#[derive(Serialize, Deserialize, Default)]
pub struct Tree<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    root: Option<Node<K, V>>,
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
        Tree { root: None }
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
    /// (e.g. locally part of the tree is missing, replaced by a placeholder), [`KeyBehindPlacehodler`] is returned.
    /// 
    /// [`KeyNonExistant`]: error/enum.MerkleError.html
    /// [`KeyBehindPlacehodler`]: error/enum.MerkleError.html
    /// 
    /// # Examples
    ///
    /// ```
    /// extern crate merkle;
    /// use merkle::Tree;
    /// use merkle::error::MerkleError::KeyNonExistant;
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
        match &self.root {
            None => Err(MerkleError::KeyNonExistant),
            Some(r) => r.get(k, 0),
        }
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
        match self.root.take() {
            None => {
                self.root = Some(Leaf::new(k, v).into());
                None
            }
            Some(n) => match n.insert(k, v, 0) {
                (v @ _, n @ _) => {
                    self.root = Some(n);
                    v
                }
            },
        }
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

    /// Returns a proof that the key is or is not present in the tree.
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
    /// use merkle::error::MerkleError::{KeyBehindPlaceholder, KeyNonExistant};
    ///
    /// let mut tree = Tree::new();
    /// tree.insert(1, "a");
    /// tree.insert(2, "b");
    /// 
    /// let proof = tree.get_proof(&1).unwrap();    // Existence proof
    /// assert!(tree.validate(&proof));
    /// assert_eq!(proof.get(&1), Ok(&"a"));
    /// assert_eq!(proof.get(&2), Err(KeyBehindPlaceholder));
    /// 
    /// let proof = tree.get_proof(&3).unwrap();    // Deniability proof (non-existence)
    /// assert!(tree.validate(&proof));
    /// assert_eq!(proof.get(&3), Err(KeyNonExistant));
    /// ```
    pub fn get_proof<Q: ?Sized>(&self, k: &Q) -> Result<Proof<K, V>, MerkleError> 
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        match &self.root {
            None => Err(MerkleError::KeyNonExistant),
            Some(r) => match r.get_proof_single(k, 0) {
                Err(r) => Err(r),
                Ok(n) => Ok(Tree { root: Some(n) }),
            },
        }
    }

    /// Returns `true` if the given proof/tree is valid (its associations are valid),
    /// from the point of view of this tree.
    /// 
    /// Outdated proofs (compared to the tree) are considered invalid.
    /// 
    /// Empty proofs are always valid.
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
        match (&self.root, &proof.root) {
            (None, _) => panic!("Validating tree is empty"),
            (Some(_), None) => true,
            (Some(n), Some(p)) => n.hash() == p.hash(),
        }
    }
}

/// A merkle proof. Used in the context of a *validating* tree (usually incomplete).
pub type Proof<K, V> = Tree<K, V>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert() {
        let mut tree = Tree::new();
        assert_eq!(tree.insert("Alice", 1), None);
        tree.insert("Alice", 2);
        assert_eq!(tree.insert("Alice", 3), Some(2));
        assert_eq!(tree.get("Alice"), Ok(&3));
    }
}
