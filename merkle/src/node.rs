// TODO: REMOVE THIS LATER!
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::convert::TryFrom;

use super::util::{bit, set_bit, clear_bits_to_end};

use drop::crypto::{self, Digest};
use std::fmt;

pub use crate::error::MerkleError::{
    self, KeyBehindPlaceholder, KeyNonExistant,
};

macro_rules! h2d {
    ($data:expr) => {
        Digest::try_from($data).expect("failed to create digest")
    };
}

const DEFAULT_HASH_DATA: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub trait Hashable {
    fn hash(&self) -> Digest;
}

impl Hashable for String {
    fn hash(&self) -> Digest {
        crypto::hash(&self).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Hash)]
pub enum Node<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    Internal(Internal<K, V>),
    Placeholder(Placeholder),
    Leaf(Leaf<K, V>),
}

impl<K, V> Node<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    fn is_leaf(&self) -> bool {
        match self {
            Node::Leaf(_) => true,
            _ => false,
        }
    }

    fn is_internal(&self) -> bool {
        match self {
            Node::Internal(_) => true,
            _ => false,
        }
    }

    pub fn is_placeholder(&self) -> bool {
        match self {
            Node::Placeholder(_) => true,
            _ => false,
        }
    }

    /// Returns the `Node<K,V>` as a `Leaf<K,V>` node.
    ///
    /// # Panics
    ///
    /// Panics if the underlying variant is not a `Leaf`.
    pub fn leaf(self) -> Leaf<K, V> {
        match self {
            Node::Leaf(n) => n,
            _ => panic!("not a leaf node"),
        }
    }

    /// Returns the `&Node<K,V>` as a `&Leaf<K,V>` node.
    ///
    /// # Panics
    ///
    /// Panics if the underlying variant is not a `Leaf`.
    pub fn leaf_ref(&self) -> &Leaf<K, V> {
        match self {
            Node::Leaf(n) => n,
            _ => panic!("not a leaf node"),
        }
    }

    /// Returns the `Node<K,V>` as an `Internal<K,V>` node.
    ///
    /// # Panics
    ///
    /// Panics if the underlying variant is not an `Internal`.
    pub fn internal(self) -> Internal<K, V> {
        match self {
            Node::Internal(n) => n,
            _ => panic!("not an internal node"),
        }
    }

    /// Returns the `&Node<K,V>` as an `&Internal<K,V>` node.
    ///
    /// # Panics
    ///
    /// Panics if the underlying variant is not an `Internal`.
    pub fn internal_ref(&self) -> &Internal<K, V> {
        match self {
            Node::Internal(n) => n,
            _ => panic!("not an internal node"),
        }
    }

    /// Returns the `Node<K,V>` as a `Placeholder` node.
    ///
    /// # Panics
    ///
    /// Panics if the underlying variant is not a `Placeholder`.
    pub fn placeholder(self) -> Placeholder {
        match self {
            Node::Placeholder(n) => n,
            _ => panic!("not a placeholder node"),
        }
    }

    /// Returns the `&Node<K,V>` as a `&Placeholder` node.
    ///
    /// # Panics
    ///
    /// Panics if the underlying variant is not a `Placeholder`.
    pub fn placeholder_ref(&self) -> &Placeholder {
        match self {
            Node::Placeholder(n) => n,
            _ => panic!("not a placeholder node"),
        }
    }

    /// Tries to return the value associated to key k from the underlying tree.
    /// depth is the depth of the current node in the tree (between 0 and 255).
    ///
    /// # Errors
    ///
    /// If the key association does not exist, or the key association is not present
    /// in the local structure, returns an error.
    pub fn get<Q: ?Sized>(&self, k: &Q, depth: u32) -> Result<&V, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        let d = crypto::hash(&k).unwrap();
        self.get_internal(k, depth, &d)
    }

    /// Tries to return the value associated to key k from the underlying tree.
    /// k_digest must be the digest of k using `crypto::hash()`.
    /// depth is the depth of the current node in the tree (between 0 and 255).
    fn get_internal<Q: ?Sized>(
        &self,
        k: &Q,
        depth: u32,
        k_digest: &Digest,
    ) -> Result<&V, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        match self {
            Node::Internal(i) => i.get_internal(k, depth, k_digest),
            Node::Placeholder(ph) => Err(KeyBehindPlaceholder(ph.hash())),
            Node::Leaf(l) => l.get_internal(k),
        }
    }
    
    pub fn extend_knowledge<Q: ?Sized>(self, k: &Q, new_count: usize, other_root: &Node<K, V>, depth: u32) -> Option<Self>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        let d = crypto::hash(&k).unwrap();
        self.extend_knowledge_internal(k, new_count, other_root, depth, &d)
    }

    fn extend_knowledge_internal<Q: ?Sized>(
        self,
        k: &Q,
        new_count: usize,
        other_root: &Node<K, V>,
        depth: u32,
        k_digest: &Digest,
    ) -> Option<Self>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        match self {
            Node::Internal(i) => Some(i.extend_knowledge_internal(k, new_count, other_root, depth, k_digest).into()),
            Node::Placeholder(ph) => match other_root.find_in_path(k, &ph.hash(), 0) {
                Ok(Some(n)) => {
                    let mut n = n.clone();
                    n.set_count(new_count);
                    Some(n)
                }
                Ok(None) => None,
                Err(()) => panic!("Attempting to extend knowledge with an ignorant other_root"),
            }
            Node::Leaf(l) => Some(l.into()),
        }
    }

    /// Returns the node in the path to the key with the same digest as the one provided (sd), if it exists
    /// 
    /// Ok(None) is returned if the provided digest is the default and the path leads to an empty leaf.
    /// (None corresponds to the empty leaf)
    pub fn find_in_path<Q: ?Sized>(&self, k: &Q, sd: &Digest, depth: u32) -> Result<Option<&Node<K, V>>, ()>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        let d = crypto::hash(&k).unwrap();
        self.find_in_path_internal(k, sd, depth, &d)
    }

    fn find_in_path_internal<Q: ?Sized>(
        &self,
        k: &Q,
        sd: &Digest,
        depth: u32,
        k_digest: &Digest,
    ) -> Result<Option<&Node<K, V>>, ()>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        match self {
            Node::Internal(i) if &i.hash() == sd => Ok(Some(&self)),
            Node::Internal(i) => i.find_in_path_internal(k, sd, depth, k_digest),
            Node::Placeholder(ph) if &ph.hash() == sd => Ok(Some(&self)),
            Node::Placeholder(_) => Err(()),
            Node::Leaf(l) if &l.hash() == sd => Ok(Some(&self)),
            Node::Leaf(_) => Err(()),
        }
    }

    /// Inserts a key-value pair into the underlying tree.
    /// depth is the depth of the current node in the tree (between 0 and 255).
    ///
    /// If the key is already present, updates the value.
    ///
    /// # Panics
    ///
    /// Behaviour is currently unspecified for the `Placeholder` variant,
    /// panicking with unimplemented!(...).
    pub fn insert(self, k: K, v: V, count: usize, depth: u32) -> (Option<V>, Self) {
        let d = crypto::hash(&k).unwrap();
        self.insert_internal(k, v, count, depth, &d)
    }

    /// Adds the key value (k, v) association to the underlying tree.
    /// k_digest must be the digest of k using `crypto::hash()`.
    /// depth is the depth of the current node in the tree (between 0 and 255).
    ///
    /// If the key is already present, updates the value.
    fn insert_internal(
        self,
        k: K,
        v: V,
        count: usize,
        depth: u32,
        k_digest: &Digest,
    ) -> (Option<V>, Self) {
        match self {
            Node::Internal(n) => match n.insert_internal(k, v, count, depth, k_digest)
            {
                (v @ _, n @ _) => (v, n.into()),
            },
            Node::Placeholder(_) => unimplemented!(
                "Unspecified behaviour for 'insert' on placeholder"
            ),
            Node::Leaf(n) => match n.insert_internal(k, v, count, depth, k_digest) {
                (v @ _, n @ _) => (v, n.into()),
            },
        }
    }

    /// Removes the key value (k, v) association to the underlying tree, if it exists.
    /// Returns the value previously associated to the key, as well as the replacement
    /// node for the current node.
    /// 'depth' is the depth of the current node in the tree (between 0 and 255).
    ///
    /// # Panics
    ///
    /// Behaviour is currently unspecified for the `Placeholder` variant,
    /// panicking with unimplemented!(...).
    pub fn remove<Q: ?Sized>(
        self,
        k: &Q,
        depth: u32,
    ) -> (Option<V>, Option<Self>)
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        let d = crypto::hash(&k).unwrap();
        self.remove_internal(k, depth, &d)
    }

    /// Removes the key value (k, v) association to the underlying tree, if it exists.
    /// Returns the value previously associated to the key, as well as the replacement
    /// node for the current node.
    /// depth is the depth of the current node in the tree (between 0 and 255).
    /// k_digest must be the digest of k using `crypto::hash()`.
    fn remove_internal<Q: ?Sized>(
        self,
        k: &Q,
        depth: u32,
        k_digest: &Digest,
    ) -> (Option<V>, Option<Self>)
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        match self {
            Node::Internal(i) => match i.remove_internal(k, depth, k_digest) {
                (v, a) => (v, Some(a)),
            },
            Node::Placeholder(_) => unimplemented!(
                "Unspecified behaviour for 'remove' on placeholder"
            ),
            Node::Leaf(l) => match l.remove_internal(k) {
                (v @ _, Some(l)) => (v, Some(l.into())),
                (v @ _, None) => (v, None),
            },
        }
    }

    pub fn replace_with_placeholder<Q: ?Sized, F>(
        self,
        k: &Q,
        max_count: usize,
        is_close: &F,
        depth: u32,
    ) -> Self
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
        F: Fn([u8; 32], usize) -> bool,
    {
        let d = crypto::hash(&k).unwrap();
        self.replace_with_placeholder_internal(k, max_count, is_close, depth, &d)
    }

    fn replace_with_placeholder_internal<Q: ?Sized, F>(
        self,
        k: &Q,
        max_count: usize,
        is_close: &F,
        depth: u32,
        k_digest: &Digest,
    ) -> Self
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
        F: Fn([u8; 32], usize) -> bool,
    {
        match self {
            Node::Internal(i) => i.replace_with_placeholder_internal(k, max_count, is_close, depth, k_digest),
            Node::Placeholder(_) => {
                // panic!("Placeholder already found in path to key. Can only replace leaves with placeholder!")
                self
            }
            Node::Leaf(l) => l.replace_with_placeholder_internal(k, max_count, is_close, depth, k_digest),
        }
    }

    pub fn merge_unchecked(&mut self, other: &Self) {
        match (self, other) {
            (Node::Internal(mine), Node::Internal(other)) => {
                mine.merge_unchecked(other)
            }
            (Node::Internal(_), Node::Placeholder(_)) => (), // assuming the hashes are equal (unchecked)
            (Node::Internal(_), Node::Leaf(_)) => {
                panic!("The trees should be compatible but are not");
            }
            (Node::Leaf(_), Node::Internal(_)) => {
                panic!("The trees should be compatible but are not");
            }
            (Node::Leaf(_), Node::Placeholder(_)) => (), // assuming the hashes are equal (unchecked)
            (Node::Leaf(_), Node::Leaf(_)) => (), // assuming the leaves are equal (unchecked)
            (Node::Placeholder(_), _) => {
                unreachable!();
            }
        }
    }

    /// Updates the digest caches recursively (stopping at nodes that already have them updated).
    /// 
    /// Nodes maintain the following invariant between method executions:
    /// - Digest caches are always updated.
    pub fn update_cache_recursive(&mut self) {
        match self {
            Node::Internal(i) => i.update_cache_recursive(),
            Node::Placeholder(_) => (),
            Node::Leaf(_) => (),
        }
    }

    /// Recursively clones and inserts all key-value pairs into the provided vector
    pub fn collect(&self, vec: &mut Vec<(K, V)>) {
        match self {
            Node::Internal(i) => i.collect(vec),
            Node::Placeholder(_) => (),
            Node::Leaf(l) => vec.push((l.key().clone(), l.value().clone())),
        }
    }

    /// Recursively clones and inserts all key-value pairs into the provided vector
    /// 
    /// TODO: this method should eventually be replaced with one that returns ~IntoIter<&K>
    /// (requires explicit lifetime declaration)
    pub fn collect_keys(&self, vec: &mut Vec<K>) {
        match self {
            Node::Internal(i) => i.collect_keys(vec),
            Node::Placeholder(_) => (),
            Node::Leaf(l) => vec.push(l.key().clone()),
        }
    }

    // Recursively counts the number of leaves
    pub fn len(&self) -> usize {
        match self {
            Node::Internal(i) => i.len(),
            Node::Placeholder(_) => 0,
            Node::Leaf(_) => 1,
        }
    }

    fn set_count(&mut self, new_count: usize) {
        match self {
            Node::Internal(i) => i.set_count(new_count),
            Node::Placeholder(_) => (),
            Node::Leaf(l) => l.set_count(new_count),
        }
    }

}

impl<K, V> Hashable for Node<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    fn hash(&self) -> Digest {
        match self {
            Node::Internal(n) => n.hash(),
            Node::Placeholder(n) => n.hash(),
            Node::Leaf(n) => n.hash(),
        }
    }
}

impl<K, V> From<Leaf<K, V>> for Node<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    fn from(l: Leaf<K, V>) -> Self {
        Node::Leaf(l)
    }
}

impl<K, V> From<Internal<K, V>> for Node<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    fn from(i: Internal<K, V>) -> Self {
        Node::Internal(i)
    }
}

impl<K, V> From<Placeholder> for Node<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    fn from(ph: Placeholder) -> Self {
        Node::Placeholder(ph)
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Copy, Clone, Hash)]
pub struct Leaf<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    k: K,
    v: V,

    #[serde(skip)]
    count: usize,
}

impl<K, V> Hashable for Leaf<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    fn hash(&self) -> Digest {
        crypto::hash(&self).unwrap()
    }
}

impl<K, V> Leaf<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    pub fn new(key: K, value: V, count: usize) -> Self {
        Leaf { k: key, v: value, count: count }
    }

    pub fn key(&self) -> &K {
        &self.k
    }

    pub fn value(&self) -> &V {
        &self.v
    }

    pub fn set_count(&mut self, new_count: usize) {
        self.count = new_count;
    }

    fn get_internal<Q: ?Sized>(&self, k: &Q) -> Result<&V, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        if self.k.borrow() == k {
            Ok(self.value())
        } else {
            Err(KeyNonExistant)
        }
    }

    fn insert_internal(
        mut self,
        k: K,
        v: V,
        count: usize,
        depth: u32,
        k_digest: &Digest,
    ) -> (Option<V>, Node<K, V>) {
        if self.k == k {
            let r = std::mem::replace(&mut self.v, v);
            return (Some(r), self.into());
        //unimplemented!("key value association already present");
        } else if depth == 255 {
            panic!("hash collision detected!");
        }

        let my_k = crypto::hash(&self.k).unwrap();

        let i = if bit(my_k.as_ref(), depth as u8) {
            Internal::new(None, Some(self.into()))
        } else {
            Internal::new(Some(self.into()), None)
        };

        match i.insert_internal(k, v, count, depth, k_digest) {
            (v @ _, n @ _) => (v, n.into()),
        }
    }

    fn remove_internal<Q: ?Sized>(self, k: &Q) -> (Option<V>, Option<Self>)
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        if self.k.borrow() == k {
            (Some(self.v), None)
        } else {
            (None, Some(self)) // consider refactoring (return an error)
        }
    }

    fn replace_with_placeholder_internal<Q: ?Sized, F>(
        self,
        k: &Q,
        max_count: usize,
        is_close: F,
        depth: u32,
        k_digest: &Digest,
    ) -> Node<K, V>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
        F: Fn([u8; 32], usize) -> bool,
    {
        if self.k.borrow() != k {
            // panic!("Attempting to replace non-existing key with placeholder");
            self.into()
        } else if self.count <= max_count && !is_close(*k_digest.as_ref(), depth as usize) {
            Placeholder::from(self).into()
        } else {
            self.into()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Hash)]
struct DigestCache {
    digest: Digest,
    updated: bool,
}

impl Default for DigestCache {
    fn default() -> Self {
        DigestCache{ digest: h2d!(DEFAULT_HASH_DATA), updated: false }
    }
}

impl DigestCache {
    fn is_updated(&self) -> bool {
        self.updated
    }

    fn update(&mut self, d: Digest) {
        self.digest = d;
        self.updated = true;
    }

    fn outdate(&mut self) {
        self.updated = false;
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Hash)]
pub struct Internal<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    left: Option<Box<Node<K, V>>>,
    right: Option<Box<Node<K, V>>>,

    #[serde(skip)]
    cached: DigestCache,
}

impl<K, V> Hashable for Internal<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    fn hash(&self) -> Digest {
        if let (None, None) = (&self.left, &self.right) {
            panic!("Internal node must have at least one child.")
        }

        if self.cached.is_updated() {
            return self.cached.digest;
        } else {
            panic!("Cached digest is not updated!");
        }
    }
}

impl<K, V> Internal<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    fn new(left: Option<Node<K, V>>, right: Option<Node<K, V>>) -> Self {
        let left = match left {
            Some(n) => Some(Box::new(n)),
            None => None,
        };
        let right = match right {
            Some(n) => Some(Box::new(n)),
            None => None,
        };
        let mut i = Internal { left, right, cached: DigestCache::default() };
        i.update_digest();
        i
    }

    fn update_cache_recursive(&mut self) {
        if !self.cached.is_updated() {
            match &mut self.left {
                Some(n) => n.update_cache_recursive(),
                None => (),
            };
    
            match &mut self.right {
                Some(n) => n.update_cache_recursive(),
                None => (),
            };
            
            self.update_digest();
        }
    }

    fn update_digest(&mut self) {
        let default_hash = h2d!(DEFAULT_HASH_DATA);

        let left_h = match &self.left {
            Some(x) => x.as_ref().hash(),
            None => default_hash,
        };
        let right_h = match &self.right {
            Some(x) => x.as_ref().hash(),
            None => default_hash,
        };
        
        let hash = crypto::hash(&(left_h, right_h)).unwrap();
        self.cached.update(hash);
    }

    fn outdate_digest(&mut self) {
        self.cached.outdate();
    }

    fn left(&self) -> Option<&Node<K, V>> {
        match &self.left {
            None => None,
            Some(b) => Some(b.as_ref()),
        }
    }

    fn right(&self) -> Option<&Node<K, V>> {
        match &self.right {
            None => None,
            Some(b) => Some(b.as_ref()),
        }
    }

    fn get_internal<Q: ?Sized>(
        &self,
        k: &Q,
        depth: u32,
        k_digest: &Digest,
    ) -> Result<&V, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        let side = if bit(k_digest.as_ref(), depth as u8) {
            &self.right
        } else {
            &self.left
        };

        match side {
            Some(n) => n.as_ref().get_internal(k, depth + 1, k_digest),
            None => Err(KeyNonExistant),
        }
    }

    fn extend_knowledge_internal<Q: ?Sized>(
        mut self,
        k: &Q,
        new_count: usize,
        other_root: &Node<K, V>,
        depth: u32,
        k_digest: &Digest,
    ) -> Self
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        let side = if bit(k_digest.as_ref(), depth as u8) {
            &mut self.right
        } else {
            &mut self.left
        };

        let r = match side.take() {
            Some(n) => match n.extend_knowledge_internal(k, new_count, other_root, depth + 1, k_digest) {
                Some(n) => Some(Box::new(n)),
                None => None,
            },
            None => None,
        };

        *side = r;

        self
    }

    fn find_in_path_internal<Q: ?Sized>(
        &self,
        k: &Q,
        sd: &Digest,
        depth: u32,
        k_digest: &Digest,
    ) -> Result<Option<&Node<K, V>>, ()>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        let side = if bit(k_digest.as_ref(), depth as u8) {
            &self.right
        } else {
            &self.left
        };

        match side {
            Some(n) => n.as_ref().find_in_path_internal(k, sd, depth + 1, k_digest),
            None if sd == &Placeholder::default().hash() => Ok(None),
            None => Err(()),
        }
    }

    fn insert_internal(
        mut self,
        k: K,
        v: V,
        count: usize,
        depth: u32,
        k_digest: &Digest,
    ) -> (Option<V>, Self) {
        self.outdate_digest();

        let side = if bit(k_digest.as_ref(), depth as u8) {
            &mut self.right
        } else {
            &mut self.left
        };

        match side.take() {
            None => {
                *side = Some(Box::new(Leaf::new(k, v, count).into()));
                self.update_digest();
                (None, self)
            }
            Some(n) => match n.insert_internal(k, v, count, depth + 1, k_digest) {
                (o @ _, n @ _) => {
                    *side = Some(Box::new(n));
                    self.update_digest();
                    (o, self)
                }
            },
        }
    }

    fn remove_internal<Q: ?Sized>(
        mut self,
        k: &Q,
        depth: u32,
        k_digest: &Digest,
    ) -> (Option<V>, Node<K, V>)
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        let side = if bit(k_digest.as_ref(), depth as u8) {
            &mut self.right
        } else {
            &mut self.left
        };

        match side.take() {
            None => (None, self.into()),
            Some(n) => {
                let r = n.remove_internal(k, depth + 1, k_digest);
                *side = match r.1 {
                    Some(a) => Some(Box::new(a)),
                    None => None,
                };

                match (&self.left, &self.right) {
                    (None, None) => panic!("Impossible"),
                    (Some(n), None) if !n.is_internal() => {
                        (r.0, *self.left.unwrap())
                    }
                    (None, Some(n)) if !n.is_internal() => {
                        (r.0, *self.right.unwrap())
                    }
                    _ => {
                        self.update_digest();
                        (r.0, self.into())
                    }
                }
            }
        }
    }

    fn replace_with_placeholder_internal<Q: ?Sized, F>(
        mut self,
        k: &Q,
        max_count: usize,
        is_close: &F,
        depth: u32,
        k_digest: &Digest,
    ) -> Node<K, V>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
        F: Fn([u8; 32], usize) -> bool,
    {
        let side = if bit(k_digest.as_ref(), depth as u8) {
            &mut self.right
        } else {
            &mut self.left
        };

        match side.take() {
            None => {
                // panic!("Attempting to replace non-existing key with placeholder")
                self.into()
            }
            Some(n) => {
                let r = n.replace_with_placeholder_internal(k, max_count, is_close, depth + 1, k_digest);
                *side = Some(Box::new(r));

                match (&self.left, &self.right) {
                    (None, None) => unreachable!(),
                    (Some(a), Some(b)) if a.is_placeholder() && b.is_placeholder() => {
                        Placeholder::from(self).into()
                    }
                    (Some(a), None) if a.is_placeholder() => {
                        let mut fake = k_digest.as_ref().clone();
                        clear_bits_to_end(&mut fake, depth as u8);
                        set_bit(&mut fake, depth as u8, true);

                        if !is_close(fake, depth as usize) {
                            Placeholder::from(self).into()
                        } else {
                            self.into()
                        }
                    }
                    (None, Some(b)) if b.is_placeholder() => {
                        let mut fake = k_digest.as_ref().clone();
                        clear_bits_to_end(&mut fake, depth as u8);

                        if !is_close(fake, depth as usize) {
                            Placeholder::from(self).into()
                        } else {
                            self.into()
                        }
                    }
                    _ => {
                        self.into()
                    }
                }
            }
        }
    }

    fn merge_unchecked(&mut self, other: &Self) {
        match (&mut self.left, other.left()) {
            (None, None) => (),
            (None, Some(b)) if b.is_placeholder() => (),
            (Some(a), None) if a.is_placeholder() => {
                self.left = None;
            }
            (Some(a), Some(b)) if a.is_placeholder() && b.is_placeholder() => {
                ()
            }
            (Some(a), Some(b)) if a.is_placeholder() => {
                self.left = Some(Box::new(b.clone()));
            }
            (Some(a), Some(b)) => {
                a.merge_unchecked(b);
            }
            (_, _) => {
                panic!("The trees should be compatible but are not");
            }
        }

        match (&mut self.right, other.right()) {
            (None, None) => (),
            (None, Some(b)) if b.is_placeholder() => (),
            (Some(a), None) if a.is_placeholder() => {
                self.right = None;
            }
            (Some(a), Some(b)) if a.is_placeholder() && b.is_placeholder() => {
                ()
            }
            (Some(a), Some(b)) if a.is_placeholder() => {
                self.right = Some(Box::new(b.clone()));
            }
            (Some(a), Some(b)) => {
                a.merge_unchecked(b);
            }
            (_, _) => {
                panic!("The trees should be compatible but are not");
            }
        }
    }

    pub fn collect(&self, vec: &mut Vec<(K, V)>) {
        match &self.left {
            None => (),
            Some(n) => n.collect(vec),
        }
        match &self.right {
            None => (),
            Some(n) => n.collect(vec),
        }
    }

    fn collect_keys(&self, vec: &mut Vec<K>) {
        match &self.left {
            None => (),
            Some(n) => n.collect_keys(vec),
        }
        match &self.right {
            None => (),
            Some(n) => n.collect_keys(vec),
        }
    }

    fn len(&self) -> usize {
        let l_len = match &self.left {
            None => 0,
            Some(n) => n.len(),
        };

        let r_len = match &self.right {
            None => 0,
            Some(n) => n.len(),
        };

        l_len + r_len
    }

    fn set_count(&mut self, new_count: usize) {
        match &mut self.left {
            None => (),
            Some(n) => n.set_count(new_count),
        };

        match &mut self.right {
            None => (),
            Some(n) => n.set_count(new_count),
        };
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Copy, Hash)]
pub struct Placeholder {
    d: Digest,
}

impl Default for Placeholder {
    fn default() -> Self {
        Placeholder {
            d: h2d!(DEFAULT_HASH_DATA),
        }
    }
}

impl fmt::Debug for Placeholder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Placeholder {{{}}}:", self.d)
    }
}

impl Placeholder {
    pub fn new(d: Digest) -> Self {
        Placeholder { d }
    }
}

impl Hashable for Placeholder {
    fn hash(&self) -> Digest {
        self.d
    }
}

impl<K, V> From<Leaf<K, V>> for Placeholder
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    fn from(l: Leaf<K, V>) -> Self {
        Placeholder { d: l.hash() }
    }
}

impl<K, V> From<Internal<K, V>> for Placeholder
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    fn from(i: Internal<K, V>) -> Self {
        Placeholder { d: i.hash() }
    }
}

impl<K, V> From<&Node<K, V>> for Placeholder
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    fn from(n: &Node<K, V>) -> Self {
        Placeholder { d: n.hash() }
    }
}

impl<K, V> From<Node<K, V>> for Placeholder
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    fn from(n: Node<K, V>) -> Self {
        match n {
            Node::Placeholder(n) => n,
            a => Placeholder::new(a.hash()),
        }
    }
}

// MERKLE PROOFs

impl<K, V> Node<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    pub fn get_proof_single<Q: ?Sized>(
        &self,
        k: &Q,
        depth: u32,
    ) -> Result<Self, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        let d = crypto::hash(&k).unwrap();
        self.get_proof_single_internal(k, depth, &d)
    }

    fn get_proof_single_internal<Q: ?Sized>(
        &self,
        key: &Q,
        depth: u32,
        k_digest: &Digest,
    ) -> Result<Self, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        match self {
            Node::Internal(n) => {
                match n.get_proof_single_internal(key, depth, k_digest) {
                    Ok(n) => Ok(n.into()),
                    Err(e) => Err(e),
                }
            }
            Node::Placeholder(ph) => Err(KeyBehindPlaceholder(ph.hash())),
            Node::Leaf(n) => match n.get_proof_single_internal(key) {
                Ok(n) => Ok(n.into()),
                Err(e) => Err(e),
            },
        }
    }
}

impl<K, V> Leaf<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    #![allow(dead_code)]
    fn get_proof_single_internal<Q: ?Sized>(
        &self,
        key: &Q,
    ) -> Result<Self, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        if self.k.borrow() == key {
            Ok(self.clone()) // Proof of Existence
        } else {
            Ok(self.clone()) // Proof of Deniability
        }
    }
}

impl<K, V> Internal<K, V>
where
    K: Serialize + Clone + Eq,
    V: Serialize + Clone,
{
    #![allow(dead_code)]
    fn get_proof_single_internal<Q: ?Sized>(
        &self,
        k: &Q,
        depth: u32,
        k_digest: &Digest,
    ) -> Result<Self, MerkleError>
    where
        K: Borrow<Q>,
        Q: Serialize + Eq,
    {
        let (side_a, side_b) = if bit(k_digest.as_ref(), depth as u8) {
            (&self.right, &self.left)
        } else {
            (&self.left, &self.right)
        };

        let side_a = match side_a {
            Some(n) => match n.as_ref().get_proof_single_internal(
                k,
                depth + 1,
                k_digest,
            ) {
                Err(e) => {
                    return Err(e);
                }
                Ok(n) => Some(n),
            },
            None => None, // Proof of Deniability (instead of returning an error)
        };

        let side_b = match side_b {
            None => Some(Placeholder::default().into()),
            Some(n) => Some(Placeholder::new(n.hash()).into()),
        };

        if bit(k_digest.as_ref(), depth as u8) {
            Ok(Internal::new(side_b, side_a))
        } else {
            Ok(Internal::new(side_a, side_b))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::util::{get_is_close_fn};
    // CONSTRUCTOR TESTS

    #[test]
    fn leaf_constructor() {
        let l = Leaf::new("Test", 3, 0);
        assert_eq!(l.k, "Test");
        assert_eq!(l.v, 3);
    }

    #[test]
    fn internal_constructor1() {
        let left_r = Leaf::new("left", 0x00, 0).into();
        let right_r = Leaf::new("right", 0x01, 0).into();
        let i = Internal::new(Some(left_r), Some(right_r));

        match (i.left.unwrap().as_ref(), i.right.unwrap().as_ref()) {
            (Node::Leaf(l), Node::Leaf(r)) => {
                assert_eq!(*l.key(), "left");
                assert_eq!(*l.value(), 0x00);
                assert_eq!(*r.key(), "right");
                assert_eq!(*r.value(), 0x01);
            }
            _ => panic!("one of the child nodes was not a leaf"),
        };
    }

    #[test]
    fn internal_constructor2() {
        let left_r = Leaf::new("left", 0x00, 0).into();
        let right_r = Leaf::new("right", 0x01, 0).into();
        let i1 = Internal::new(Some(left_r), Some(right_r));
        let i2 = Internal::new(Some(i1.into()), None);

        match (i2.left().unwrap(), i2.right()) {
            (Node::Internal(i), None) => {
                match (i.left().unwrap(), i.right().unwrap()) {
                    (Node::Leaf(l), Node::Leaf(r)) => {
                        assert_eq!(*l.key(), "left");
                        assert_eq!(*l.value(), 0x00);
                        assert_eq!(*r.key(), "right");
                        assert_eq!(*r.value(), 0x01);
                    }
                    _ => panic!("one of the child nodes of the left internal node was not a leaf"),
                };
            }
            (_, Some(_)) => panic!("right child not None"),
            _ => panic!("wrong cast for children"),
        }
    }

    #[test]
    fn placeholder_from_leaf() {
        let base = Leaf::new("", 0x00, 0);
        let hash = base.hash();

        let ph: Placeholder = base.into();
        assert_eq!(ph.d, hash);
    }

    #[test]
    fn placeholder_from_internal() {
        let base = Leaf::new("", 0x00, 0);
        let i = Internal::new(None, Some(base.into()));
        let hash = i.hash();

        let ph: Placeholder = i.into();
        assert_eq!(ph.d, hash);
    }

    // HASH CORRECTNESS TESTS

    #[test]
    fn leaf_hash() {
        let base = Leaf::new("", 0x00, 0);

        let r1 = Leaf::new("", 0x01, 0);
        assert_ne!(base.hash(), r1.hash());

        let r2 = Leaf::new("", 0x00, 0);
        assert_eq!(base.hash(), r2.hash());

        let v: [u8; 0] = [];
        let r3 = Leaf::new("", v, 0);
        assert_ne!(base.hash(), r3.hash());
    }

    #[test]
    fn internal_hash_correctness1() {
        let left_r = Leaf::new("left", 0x00, 0).into();
        let right_r = Leaf::new("right", 0x01, 0).into();
        let i = Internal::new(Some(left_r), Some(right_r));
        let h1 = i.hash();
        let p1 = Internal::new(Some(i.into()), None);

        let left_r = Leaf::new("left", 0x00, 0).into();
        let right_r = Leaf::new("right", 0x01, 0).into();
        let i = Internal::new(Some(left_r), Some(right_r));
        let h2 = i.hash();
        let p2 = Internal::new(Some(i.into()), None);

        assert_eq!(h1, h2);
        assert_eq!(p1.hash(), p2.hash());
    }

    macro_rules! test_hash {
        ($data:expr) => {
            crypto::hash(&($data)).expect("failed to hash data")
        };
    }

    #[test]
    fn placeholder_constructor() {
        let ph = Placeholder::new(test_hash!(0u32));

        assert_eq!(ph.hash(), test_hash!(0u32));
        assert_eq!(ph.d, test_hash!(0u32));
    }

    // GET TESTS

    #[test]
    fn leaf_get_normal() {
        let base = Leaf::new("Alice", 0x00, 0);

        let v = base.get_internal("Alice").unwrap();
        assert_eq!(*v, 0x00);
    }

    #[test]
    #[should_panic(expected = "KeyNonExistant")]
    fn leaf_get_err_non_existant() {
        let base = Leaf::new("Alice", 0x00, 0);

        base.get_internal("Bob").unwrap();
    }

    #[test]
    fn internal_get_normal() {
        let i: Node<_, _> = Internal::new(None, None).into();
        let (_, i) = i.insert("Alice", 0x01, 0, 0);
        let (_, i) = i.insert("Bob", 0x02, 0, 0);

        let v = i.get("Alice", 0).unwrap();
        assert_eq!(*v, 0x01);

        let v = i.get("Bob", 0).unwrap();
        assert_eq!(*v, 0x02);
    }

    #[test]
    #[should_panic(expected = "KeyNonExistant")]
    fn internal_get_err_non_existant() {
        let i: Node<_, _> = Internal::new(None, None).into();
        let (_, i) = i.insert("Alice", 0x01, 0, 0);
        let (_, i) = i.insert("Bob", 0x02, 0, 0);

        i.get("Charlie", 0).unwrap();
    }

    #[test]
    #[should_panic(expected = "KeyBehindPlaceholder")]
    fn internal_get_err_behind_placeholder() {
        let i: Node<_, _> = Internal::new(None, None).into();
        let (_, i) = i.insert("Bob", 0x01, 0, 0); // left
        let (_, i) = i.insert("Aaron", 0x02, 0, 0); // right, left
        let mut i = i.insert("Dave", 0x03, 0, 0).1.internal(); // right, right

        let ph: Placeholder = i.right().unwrap().into();
        i.right = Some(Box::new(ph.into()));
        let i: Node<_, _> = i.into();

        let v = i.get("Bob", 0).unwrap();
        assert_eq!(*v, 0x01);

        i.get("Aaron", 0).unwrap();
    }

    // INSERT TESTS

    // Initially there is only one leaf which key hash starts with b1...
    // We insert (k,v) such that hash(k) starts with b0...
    // The addition should therefore return an Internal node with children:
    //  - left:     Leaf(k,v)
    //  - right:    original leaf node
    #[test]
    fn leaf_insert1() {
        let leaf_k = "left";
        let leaf_d = crypto::hash(&leaf_k).unwrap();
        assert_eq!(
            leaf_d,
            h2d!("c8c3fff091d468a9c3d758eb79f31b0e9cef2718681b81ec693d0990a639962f")
        );

        let leaf = Leaf::new(leaf_k, 0x00, 0);

        let k = "Bob";
        let digest = crypto::hash(&k).unwrap();
        assert_eq!(
            digest,
            h2d!("63688fc040203caed5265b7c08f5a5627ba260c2004ed1241fa859dd02160f54")
        );

        assert_eq!(bit(digest.as_ref(), 0), false);
        assert_eq!(bit(leaf_d.as_ref(), 0), true);

        let depth = 0;
        let i = leaf.insert_internal(k, 0x01, 0, depth, &digest).1.internal();

        if let Node::Leaf(l) = i.left().expect("missing left node") {
            assert_eq!(l.k, "Bob");
            assert_eq!(l.v, 0x01);
        } else {
            panic!("left node not leaf");
        }

        if let Node::Leaf(r) = i.right().expect("missing right node") {
            assert_eq!(r.k, "left");
            assert_eq!(r.v, 0x00);
        } else {
            panic!("right node not leaf");
        }
    }

    // Initially there is only one leaf which key hash starts with b11...
    // We insert (k,v) such that hash(k) starts with b10...
    // The addition should therefore return an Internal node with children:
    //  - left:     None
    //  - right:    Internal
    //      -- left:    Leaf(k,v)
    //      -- right:   original leaf node
    #[test]
    fn leaf_insert2() {
        let leaf_k = "left";
        let leaf_d = crypto::hash(&leaf_k).unwrap();
        assert_eq!(
            leaf_d,
            h2d!("c8c3fff091d468a9c3d758eb79f31b0e9cef2718681b81ec693d0990a639962f")
        );

        let leaf = Leaf::new(leaf_k, 0x00, 0);

        let k = "Aaron";
        let digest = crypto::hash(&k).unwrap();
        assert_eq!(
            digest,
            h2d!("82464cbbaaf39d3d5f924f44c09feccd921816359abf54a4dcb97aa54ef94c04")
        );

        let depth = 0;
        let i = leaf.insert_internal(k, 0x01, 0, depth, &digest).1.internal();

        if let Some(_) = i.left() {
            panic!("left of depth 0 internal node should be empty");
        }

        if let Some(Node::Internal(i)) = i.right() {
            if let Node::Leaf(l) = i
                .left()
                .expect("missing left node of depth 1 internal node")
            {
                assert_eq!(l.k, "Aaron");
                assert_eq!(l.v, 0x01);
            } else {
                panic!("left node of depth 1 internal node not a leaf");
            }

            if let Node::Leaf(r) = i
                .right()
                .expect("missing right node of depth 1 internal node")
            {
                assert_eq!(r.k, "left");
                assert_eq!(r.v, 0x00);
            } else {
                panic!("right node of depth 1 internal node not a leaf");
            }
        }
    }

    #[test]
    fn leaf_insert_existing_key() {
        let leaf_k = "left";

        let leaf = Leaf::new(leaf_k, 0x01, 0);
        let digest = crypto::hash(&leaf_k).unwrap();

        let (v, i) = leaf.insert_internal(leaf_k, 0x02, 0, 0, &digest);
        assert_eq!(v, Some(0x01));
        let (v, i) = i.insert_internal(leaf_k, 0x03, 0, 0, &digest);
        assert_eq!(v, Some(0x02));
        let (v, _) = i.insert("aaron", 0x03, 0, 0);
        assert_eq!(v, None);
    }

    // Initially there is only one internal node holding a leaf which key hash starts with b1...
    // We insert (k,v) such that hash(k) starts with b0...
    // The addition should therefore return nothing.
    // The Internal node should end with children:
    //  - left:     Leaf(k,v)
    //  - right:    original leaf node
    #[test]
    fn internal_insert1() {
        let leaf_k = "left";
        let leaf_d = crypto::hash(&leaf_k).unwrap();
        assert_eq!(
            leaf_d,
            h2d!("c8c3fff091d468a9c3d758eb79f31b0e9cef2718681b81ec693d0990a639962f")
        );

        let leaf = Leaf::new(leaf_k, 0x00, 0);

        let k = "Bob";
        let digest = crypto::hash(&k).unwrap();
        assert_eq!(
            digest,
            h2d!("63688fc040203caed5265b7c08f5a5627ba260c2004ed1241fa859dd02160f54")
        );

        let depth = 0;
        let i: Node<_, _> = Internal::new(None, Some(leaf.into())).into();
        let i = i.insert(k, 0x01, 0, depth).1.internal();

        if let Node::Leaf(l) = i.left().expect("missing left node") {
            assert_eq!(l.k, "Bob");
            assert_eq!(l.v, 0x01);
        } else {
            panic!("left node not leaf");
        }

        if let Node::Leaf(r) = i.right().expect("missing left node") {
            assert_eq!(r.k, "left");
            assert_eq!(r.v, 0x00);
        } else {
            panic!("right node not a leaf");
        }
    }

    // Initially there is only one leaf which key hash starts with b11...
    // We insert (k,v) such that hash(k) starts with b10...
    // The addition should therefore return nothing.
    // The Internal node should end with children:
    //  - left:     None
    //  - right:    Internal
    //      -- left:    Leaf(k,v)
    //      -- right:   original leaf node
    #[test]
    fn internal_insert2() {
        let leaf_k = "left";
        let leaf_d = crypto::hash(&leaf_k).unwrap();
        assert_eq!(
            leaf_d,
            h2d!("c8c3fff091d468a9c3d758eb79f31b0e9cef2718681b81ec693d0990a639962f")
        );

        let leaf = Leaf::new(leaf_k, 0x00, 0);

        let k = "Aaron";
        let digest = crypto::hash(&k).unwrap();
        assert_eq!(
            digest,
            h2d!("82464cbbaaf39d3d5f924f44c09feccd921816359abf54a4dcb97aa54ef94c04")
        );

        let depth = 0;
        let i: Node<_, _> = Internal::new(None, Some(leaf.into())).into();
        let i = i.insert(k, 0x01, 0, depth).1.internal();

        if let Some(Node::Internal(i)) = i.right() {
            if let Node::Leaf(l) = i
                .left()
                .expect("missing left node of depth 1 internal node")
            {
                assert_eq!(l.k, "Aaron");
                assert_eq!(l.v, 0x01);
            } else {
                panic!("left node of depth 1 internal node not a leaf");
            }

            if let Node::Leaf(r) = i
                .right()
                .expect("missing right node of depth 1 internal node")
            {
                assert_eq!(r.k, "left");
                assert_eq!(r.v, 0x00);
            } else {
                panic!("right node of depth 1 internal node not a leaf");
            }
        }
    }

    #[test]
    fn internal_insert_existing_key() {
        let i: Node<_, _> = Leaf::new("left", 0x01, 0).into();
        let (_, i) = i.insert("right", 0x02, 0, 0);

        let (v, i) = i.insert("right", 0x03, 0, 0);
        assert_eq!(v, Some(0x02));

        let (v, i) = i.insert("left", 0x04, 0, 0);
        assert_eq!(v, Some(0x01));

        let (v, _) = i.insert("aaron", 0x03, 0, 0);
        assert_eq!(v, None);
    }

    // REMOVE TESTS

    #[test]
    fn leaf_remove_normal() {
        let l: Node<_, _> = Leaf::new("Alice", 0x01, 0).into();
        let v = l.remove("Alice", 0);
        assert_eq!(v.0, Some(0x01));
        if let Some(_) = v.1 {
            panic!("should return None for node");
        }
    }

    #[test]
    fn leaf_remove_non_existant() {
        let l: Node<_, _> = Leaf::new("Alice", 0x01, 0).into();
        let v = l.remove("Bob", 0);
        let l = v.1.unwrap().leaf();
        assert_eq!(*l.key(), "Alice");
        assert_eq!(*l.value(), 0x01);

        if let Some(_) = v.0 {
            panic!("should return None for value");
        }
    }

    // Testing leaf return after remove.
    #[test]
    fn internal_remove_normal1() {
        let i: Node<_, _> = Internal::new(None, None).into();
        let (_, i) = i.insert("Bob", 0x01, 0, 0); // left
        let (_, i) = i.insert("Aaron", 0x02, 0, 0); // right

        let v = i.remove("Aaron", 0);
        assert_eq!(v.0, Some(0x02));
        let i = v.1.unwrap();

        if let Node::Leaf(n) = i {
            assert_eq!(*n.key(), "Bob");
            assert_eq!(*n.value(), 0x01);
        } else {
            panic!("node of depth 0 should be leaf");
        }
    }

    // Testing internal node return (with 2 children) after remove.
    #[test]
    fn internal_remove_normal2() {
        let i: Node<_, _> = Internal::new(None, None).into();
        let (_, i) = i.insert("Bob", 0x01, 0, 0); // left
        let (_, i) = i.insert("Aaron", 0x02, 0, 0); // right, left
        let (_, i) = i.insert("Dave", 0x03, 0, 0); // right, right

        let v = i.remove("Dave", 0);
        assert_eq!(v.0, Some(0x03));
        let i = v.1.unwrap().internal();

        if let Node::Leaf(n) = i.left().unwrap() {
            assert_eq!(*n.key(), "Bob");
            assert_eq!(*n.value(), 0x01);
        } else {
            panic!("left node of depth 1 should be leaf");
        }

        if let Node::Leaf(n) = i.right().unwrap() {
            assert_eq!(*n.key(), "Aaron");
            assert_eq!(*n.value(), 0x02);
        } else {
            panic!("right node of depth 1 should be leaf");
        }
    }

    // Testing leaf return after cascade remove.
    #[test]
    fn internal_remove_normal3() {
        let i: Node<_, _> = Internal::new(None, None).into();
        let (_, i) = i.insert("Bob", 0x02, 0, 0); // L,R,R,L,L,L,R,R
        let (_, i) = i.insert("Charlie", 0x03, 0, 0); // L,R,R,L,L,L,R,L

        let v = i.remove("Charlie", 0);
        assert_eq!(v.0, Some(0x03));
        let i = v.1.unwrap();

        if let Node::Leaf(n) = i {
            assert_eq!(*n.key(), "Bob");
            assert_eq!(*n.value(), 0x02);
        } else {
            panic!("node of depth 0 should be leaf");
        }
    }

    // Testing internal node return (with 2 children) after cascade remove.
    #[test]
    fn internal_remove_normal4() {
        let i: Node<_, _> = Internal::new(None, None).into();
        let (_, i) = i.insert("Aaron", 0x01, 0, 0); // right
        let (_, i) = i.insert("Bob", 0x02, 0, 0); // L,R,R,L,L,L,R,R
        let (_, i) = i.insert("Charlie", 0x03, 0, 0); // L,R,R,L,L,L,R,L

        let v = i.remove("Charlie", 0);
        assert_eq!(v.0, Some(0x03));
        let i = v.1.unwrap().internal();

        if let Node::Leaf(n) = i.left().unwrap() {
            assert_eq!(*n.key(), "Bob");
            assert_eq!(*n.value(), 0x02);
        } else {
            panic!("left node of depth 1 should be leaf");
        }

        if let Node::Leaf(n) = i.right().unwrap() {
            assert_eq!(*n.key(), "Aaron");
            assert_eq!(*n.value(), 0x01);
        } else {
            panic!("right node of depth 1 should be leaf");
        }
    }

    #[test]
    fn internal_remove_err() {
        let i: Node<_, _> = Internal::new(None, None).into();
        let (_, i) = i.insert("Aaron", 0x01, 0, 0); // right
        let (_, i) = i.insert("Bob", 0x02, 0, 0); // L,R,R,L,L,L,R,R
        let (_, i) = i.insert("Charlie", 0x03, 0, 0); // L,R,R,L,L,L,R,L

        let v = i.remove("Charlie", 0);
        assert_eq!(v.0, Some(0x03));
        let i = v.1.unwrap().internal();

        if let Node::Leaf(n) = i.left().unwrap() {
            assert_eq!(*n.key(), "Bob");
            assert_eq!(*n.value(), 0x02);
        } else {
            panic!("left node of depth 1 should be leaf")
        }

        if let Node::Leaf(n) = i.right().unwrap() {
            assert_eq!(*n.key(), "Aaron");
            assert_eq!(*n.value(), 0x01);
        } else {
            panic!("right node of depth 1 should be leaf")
        }
    }

    // SERIALIZATION TESTS

    #[test]
    fn ser_de() {
        let i: Node<_, _> = Leaf::new("Bob", 0x02, 0).into(); // L,R,R,L,L,L,R,R
        let (_, i) = i.insert("Charlie", 0x03, 0, 0); // L,R,R,L,L,L,R,L

        extern crate bincode;

        let ser = bincode::serialize(&i).unwrap();
        let g: Node<&str, i32> = bincode::deserialize(&ser).unwrap();

        assert_eq!(g.get("Bob", 0), Ok(&0x02));
        assert_eq!(g.get("Charlie", 0), Ok(&0x03));
    }

    #[test]
    #[should_panic(expected = "Cached digest is not updated!")]
    fn ser_de_err() {
        let i: Node<_, _> = Leaf::new("Bob", 0x02, 0).into(); // L,R,R,L,L,L,R,R
        let (_, i) = i.insert("Charlie", 0x03, 0, 0); // L,R,R,L,L,L,R,L

        extern crate bincode;

        let ser = bincode::serialize(&i).unwrap();
        let g: Node<&str, i32> = bincode::deserialize(&ser).unwrap();

        g.hash();
    }

    #[test]
    fn ser_de_update_cache_recursive() {
        let i: Node<_, _> = Leaf::new("Bob", 0x02, 0).into(); // L,R,R,L,L,L,R,R
        let (_, i) = i.insert("Charlie", 0x03, 0, 0); // L,R,R,L,L,L,R,L

        extern crate bincode;

        let ser = bincode::serialize(&i).unwrap();
        let mut g: Node<&str, i32> = bincode::deserialize(&ser).unwrap();

        g.update_cache_recursive();
        g.hash();
    }

    // PROOF TESTS

    #[test]
    fn leaf_get_proof_single() -> Result<(), MerkleError> {
        let l = Leaf::new("Alice", 1, 0);
        let a = l.get_proof_single_internal("Alice")?;

        assert_eq!(*a.value(), 1);
        assert_eq!(*a.key(), "Alice");

        Ok(())
    }

    #[test]
    #[should_panic(expected = "KeyNonExistant")]
    fn leaf_get_proof_single_err() {
        let l = Leaf::new("Alice", 1, 0);
        let p: Node<_, _> = l.get_proof_single_internal("Bob").unwrap().into();
        p.get("Bob", 0).unwrap();
    }

    #[test]
    fn internal_get_proof_single1() {
        let l: Node<_, _> = Leaf::new("Bob", 1, 0).into(); //left
        let (_, i) = l.insert("Aaron", 2, 0, 0); //right

        let h = crypto::hash(&"Aaron").unwrap();
        let proof = i
            .get_proof_single_internal("Aaron", 0, &h)
            .unwrap()
            .internal();

        let ph: Placeholder = Leaf::new("Bob", 1, 0).into();

        assert_eq!(*proof.left().unwrap().placeholder_ref(), ph);
        assert_eq!(*proof.right().unwrap().leaf_ref(), Leaf::new("Aaron", 2, 0));
    }

    #[test]
    fn internal_get_proof_single2() {
        let l: Node<_, _> = Leaf::new("Bob", 0x01, 0).into(); //left
        let (_, i) = l.insert("Aaron", 0x02, 0, 0); //right, left
        let (_, i) = i.insert("Dave", 0x03, 0, 0); // right, right

        let h = crypto::hash(&"Dave").unwrap();
        let proof = i
            .get_proof_single_internal("Dave", 0, &h)
            .unwrap()
            .internal();

        let ph_bob: Placeholder = Leaf::new("Bob", 0x01, 0).into();
        let ph_aar: Placeholder = Leaf::new("Aaron", 0x02, 0).into();

        let r1 = proof.right().unwrap().internal_ref();

        assert_eq!(*proof.left().unwrap().placeholder_ref(), ph_bob);
        assert_eq!(*r1.left().unwrap().placeholder_ref(), ph_aar);
        assert_eq!(*r1.right().unwrap().leaf_ref(), Leaf::new("Dave", 0x03, 0));
    }

    #[test]
    fn internal_get_proof_single3() {
        let l: Node<_, _> = Leaf::new("Bob", 0x01, 0).into(); // L,R,R,L,L,L,R,R
        let (_, i) = l.insert("Charlie", 0x03, 0, 0); // L,R,R,L,L,L,R,L
        let (_, i) = i.insert("Aaron", 0x02, 0, 0); // right (R)

        let h = crypto::hash(&"Charlie").unwrap();
        let proof = i
            .get_proof_single_internal("Charlie", 0, &h)
            .unwrap()
            .internal();

        let ph_bob: Placeholder = Leaf::new("Bob", 0x01, 0).into();
        let ph_aar: Placeholder = Leaf::new("Aaron", 0x02, 0).into();
        let ph_def: Placeholder = Placeholder::default();

        let d1 = proof.left().unwrap().internal_ref();
        let d2 = d1.right().unwrap().internal_ref();
        let d3 = d2.right().unwrap().internal_ref();
        let d4 = d3.left().unwrap().internal_ref();
        let d5 = d4.left().unwrap().internal_ref();
        let d6 = d5.left().unwrap().internal_ref();
        let d7 = d6.right().unwrap().internal_ref();

        assert_eq!(*proof.right().unwrap().placeholder_ref(), ph_aar);
        assert_eq!(*d1.left().unwrap().placeholder_ref(), ph_def);
        assert_eq!(*d2.left().unwrap().placeholder_ref(), ph_def);
        assert_eq!(*d3.right().unwrap().placeholder_ref(), ph_def);
        assert_eq!(*d4.right().unwrap().placeholder_ref(), ph_def);
        assert_eq!(*d5.right().unwrap().placeholder_ref(), ph_def);
        assert_eq!(*d6.left().unwrap().placeholder_ref(), ph_def);
        assert_eq!(*d7.right().unwrap().placeholder_ref(), ph_bob);
        assert_eq!(*d7.left().unwrap().leaf_ref(), Leaf::new("Charlie", 0x03, 0));
    }

    #[test]
    #[should_panic(expected = "KeyNonExistant")]
    fn internal_get_proof_single_err() {
        let i: Node<_, _> = Leaf::new("Bob", 0x01, 0).into(); // left (L)
        let (_, i) = i.insert("Aaron", 0x02, 0, 0); // right (R)

        let p = i.get_proof_single("Charlie", 0);
        if let Err(_) = p {
            panic!("Should return deniability proof")
        }

        p.unwrap().get("Charlie", 0).unwrap();
    }

    // MERGE

    #[test]
    fn leaf_merge() {
        let mut l: Node<_, _> = Leaf::new("Alice", 3, 0).into();
        let l2 = l.clone();

        l.merge_unchecked(&l2);
        assert_eq!(l.leaf(), Leaf::new("Alice", 3, 0));
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
    fn internal_merge() {
        let l: Node<_, _> = Leaf::new("Bob", 0x01, 0).into(); // L,R,R,L,L,L,R,R
        let (_, i) = l.insert("Charlie", 0x03, 0, 0); // L,R,R,L,L,L,R,L
        let (_, i) = i.insert("Aaron", 0x02, 0, 0); // right (R)

        let mut proof = i.get_proof_single("Charlie", 0).unwrap();
        assert_eq!(proof.get("Charlie", 0), Ok(&0x03));
        assert_behind_ph!(proof.get("Bob", 0));
        assert_behind_ph!(proof.get("Aaron", 0));

        proof.merge_unchecked(&i);
        assert_eq!(proof.get("Charlie", 0), Ok(&0x03));
        assert_eq!(proof.get("Bob", 0), Ok(&0x01));
        assert_eq!(proof.get("Aaron", 0), Ok(&0x02));
    }

    #[test]
    fn node_find_in_path() {
        let l: Node<_, _> = Leaf::new("Bob", 0x01, 0).into(); // L,R,R,L,L,L,R,R
        let (_, i) = l.insert("Charlie", 0x03, 0, 0); // L,R,R,L,L,L,R,L
        let (_, i) = i.insert("Aaron", 0x02, 0, 0); // right (R)

        let proof = i.get_proof_single("Charlie", 0).unwrap();

        let d1 = match proof.get("Aaron", 0).unwrap_err() {
            MerkleError::KeyBehindPlaceholder(d) => d,
            _ => panic!("Aaron should be behind placeholder"),
        };
        let d2 = match proof.get("Bob", 0).unwrap_err() {
            MerkleError::KeyBehindPlaceholder(d) => d,
            _ => panic!("Bob should be behind placeholder"),
        };

        match i.find_in_path("Aaron", &d1, 0) {
            Ok(Some(n)) if n.hash() != d1 => panic!("Hash of node found does not match digest"),
            Ok(Some(_)) => (),
            _ => panic!("Should have found digest in path to Aaron")
        }
        match i.find_in_path("Bob", &d2, 0) {
            Ok(Some(n)) if n.hash() != d2 => panic!("Hash of node found does not match digest"),
            Ok(Some(_)) => (),
            _ => panic!("Should have found digest in path to Bob")
        }
    }

    // Replace with placeholder

    #[test]
    fn node_replace_with_placeholder_1() {
        let me = h2d!("0000000000000000000000000000000000000000000000000000000000000000");

        let v = vec!(
            h2d!("0000000000000000000000000000000000000000000000000000000000000000"),   // L, L
            h2d!("4000000000000000000000000000000000000000000000000000000000000000"),   // L, R
            h2d!("8000000000000000000000000000000000000000000000000000000000000000"),   // R
        );

        let is_close = get_is_close_fn(me, v);

        let l: Node<_, _> = Leaf::new("Alice", 0x01, 0).into(); // L,L
        let (_, i) = l.insert("Bob", 0x02, 0, 0); // L,R
        let (_, i) = i.insert("Aaron", 0x03, 0, 0); // R

        let i = i.replace_with_placeholder("Bob", 1, &is_close, 0);
        let i = i.replace_with_placeholder("Aaron", 1, &is_close, 0);
        let i = i.replace_with_placeholder("Alice", 1, &is_close, 0).internal(); // (should not replace)

        let ph_bob: Placeholder = Leaf::new("Bob", 0x02, 0).into();
        let ph_aar: Placeholder = Leaf::new("Aaron", 0x03, 0).into();

        let d1 = i.left().unwrap().internal_ref();

        assert_eq!(*i.right().unwrap().placeholder_ref(), ph_aar);
        assert_eq!(*d1.right().unwrap().placeholder_ref(), ph_bob);
        assert_eq!(d1.left().unwrap().leaf_ref(), &Leaf::new("Alice", 0x01, 0));
    }

    #[test]
    fn node_replace_with_placeholder_2() {
        let me = h2d!("6F00000000000000000000000000000000000000000000000000000000000000");

        let v = vec!(
            h2d!("6300000000000000000000000000000000000000000000000000000000000000"),   // L,R,R,L,L,L,R,R
            h2d!("6F00000000000000000000000000000000000000000000000000000000000000"),   // L,R,R,L,R,R,R,R
            h2d!("8000000000000000000000000000000000000000000000000000000000000000"),   // R
        );

        let is_close = get_is_close_fn(me, v);

        let l: Node<_, _> = Leaf::new("Bob", 0x01, 0).into(); // L,R,R,L,L,L,R,R
        let (_, i) = l.insert("Charlie", 0x02, 0, 0); // L,R,R,L,L,L,R,L
        let (_, i) = i.insert("Aaron", 0x03, 0, 0); // right (R)

        // Get expected placeholder
        let d1 = i.internal_ref().left().unwrap().internal_ref();
        let d2 = d1.right().unwrap().internal_ref();
        let d3 = d2.right().unwrap().internal_ref();
        let d4 = d3.left().unwrap().internal_ref();
        let ph_aar: Placeholder = d4.left().unwrap().internal_ref().clone().into();

        let i = i.replace_with_placeholder("Bob", 1, &is_close, 0);
        let i = i.replace_with_placeholder("Charlie", 1, &is_close, 0).internal();

        let d1 = i.left().unwrap().internal_ref();
        let d2 = d1.right().unwrap().internal_ref();
        let d3 = d2.right().unwrap().internal_ref();
        let d4 = d3.left().unwrap().internal_ref();

        assert_eq!(i.right().unwrap().leaf_ref(), &Leaf::new("Aaron", 0x03, 0));
        assert_eq!(d1.left(), None);
        assert_eq!(d2.left(), None);
        assert_eq!(d3.right(), None);
        assert_eq!(d4.right(), None);
        assert_eq!(d4.left().unwrap().placeholder_ref(), &ph_aar);
    }

    #[test]
    fn node_replace_with_placeholder_3() {
        let me = h2d!("0000000000000000000000000000000000000000000000000000000000000000");

        let v = vec!(
            h2d!("0000000000000000000000000000000000000000000000000000000000000000"),   // L
            h2d!("8000000000000000000000000000000000000000000000000000000000000000"),   // R, L
            h2d!("c000000000000000000000000000000000000000000000000000000000000000"),   // R, R
        );

        let is_close = get_is_close_fn(me, v);

        let l: Node<_, _> = Leaf::new("Bob", 0x01, 0).into(); //left
        let (_, i) = l.insert("Aaron", 0x02, 0, 0); //right, left
        let (_, i) = i.insert("Dave", 0x03, 0, 0); // right, right
        
        let i = i.replace_with_placeholder("Dave", 1, &is_close, 0);
        let i = i.replace_with_placeholder("Aaron", 1, &is_close, 0).internal();

        let i2 = Internal::new(Some(Leaf::new("Aaron", 0x02, 0).into()), Some(Leaf::new("Dave", 0x03, 0).into()));
        let ph_aaron_dave: Placeholder = i2.into();

        assert_eq!(*i.left().unwrap().leaf_ref(), Leaf::new("Bob", 0x01, 0));
        assert_eq!(*i.right().unwrap().placeholder_ref(), ph_aaron_dave);
    }

    // Set count

    #[test]
    fn node_set_count() {
        let l: Node<_, _> = Leaf::new("Bob", 0x01, 0).into(); //left
        let (_, i) = l.insert("Aaron", 0x02, 0, 0); //right, left
        let mut i = i.internal();

        i.set_count(5);
        assert_eq!(i.left().unwrap().leaf_ref(), &Leaf::new("Bob", 0x01, 5));
        assert_eq!(i.right().unwrap().leaf_ref(), &Leaf::new("Aaron", 0x02, 5));

        let i: Node<_, _> = i.into();
        let (_, i) = i.insert("Dave", 0x03, 10, 0); //right, right
        let i = i.internal_ref();

        let d1 = i.right().unwrap().internal_ref();

        assert_eq!(i.left().unwrap().leaf_ref(), &Leaf::new("Bob", 0x01, 5));
        assert_eq!(d1.left().unwrap().leaf_ref(), &Leaf::new("Aaron", 0x02, 5));
        assert_eq!(d1.right().unwrap().leaf_ref(), &Leaf::new("Dave", 0x03, 10));
    }

    // Extend knowledge

    #[test]
    fn node_extend_knowledge_1() {
        let l: Node<_, _> = Leaf::new("Bob", 0x01, 0).into(); // L,R,R,L,L,L,R,R
        let (_, i) = l.insert("Charlie", 0x03, 0, 0); // L,R,R,L,L,L,R,L
        let (_, i) = i.insert("Aaron", 0x02, 0, 0); // right (R)

        let pseudo_proof = i.clone();

        let i = i.replace_with_placeholder("Bob", 1, &|_,_| false, 0);
        let i = i.replace_with_placeholder("Aaron", 1, &|_,_| false, 0);

        let i = i.extend_knowledge("Bob", 5, &pseudo_proof, 0).unwrap();
        let i = i.extend_knowledge("Aaron", 5, &pseudo_proof, 0).unwrap().internal();

        let d1 = i.left().unwrap().internal_ref();
        let d2 = d1.right().unwrap().internal_ref();
        let d3 = d2.right().unwrap().internal_ref();
        let d4 = d3.left().unwrap().internal_ref();
        let d5 = d4.left().unwrap().internal_ref();
        let d6 = d5.left().unwrap().internal_ref();
        let d7 = d6.right().unwrap().internal_ref();

        assert_eq!(i.right().unwrap().leaf_ref(), &Leaf::new("Aaron", 0x02, 5));
        assert_eq!(d1.left(), None);
        assert_eq!(d2.left(), None);
        assert_eq!(d3.right(), None);
        assert_eq!(d4.right(), None);
        assert_eq!(d5.right(), None);
        assert_eq!(d6.left(), None);
        assert_eq!(d7.right().unwrap().leaf_ref(), &Leaf::new("Bob", 0x01, 5));
        assert_eq!(d7.left().unwrap().leaf_ref(), &Leaf::new("Charlie", 0x03, 0));
    }

    #[test]
    fn node_extend_knowledge_2() {
        let me = h2d!("6F00000000000000000000000000000000000000000000000000000000000000");

        let v = vec!(
            h2d!("6300000000000000000000000000000000000000000000000000000000000000"),   // L,R,R,L,L,L,R,R
            h2d!("6F00000000000000000000000000000000000000000000000000000000000000"),   // L,R,R,L,R,R,R,R
            h2d!("8000000000000000000000000000000000000000000000000000000000000000"),   // R
        );

        let is_close = get_is_close_fn(me, v);

        let l: Node<_, _> = Leaf::new("Bob", 0x01, 0).into(); // L,R,R,L,L,L,R,R
        let (_, i) = l.insert("Charlie", 0x02, 0, 0); // L,R,R,L,L,L,R,L
        let (_, i) = i.insert("Aaron", 0x03, 0, 0); // right (R)

        let pseudo_proof = i.clone();

        let i = i.replace_with_placeholder("Bob", 1, &is_close, 0);
        let i = i.replace_with_placeholder("Charlie", 1, &is_close, 0);

        let i = i.extend_knowledge("Bob", 5, &pseudo_proof, 0).unwrap();
        let i = i.extend_knowledge("Charlie", 5, &pseudo_proof, 0).unwrap().internal();

        let d1 = i.left().unwrap().internal_ref();
        let d2 = d1.right().unwrap().internal_ref();
        let d3 = d2.right().unwrap().internal_ref();
        let d4 = d3.left().unwrap().internal_ref();
        let d5 = d4.left().unwrap().internal_ref();
        let d6 = d5.left().unwrap().internal_ref();
        let d7 = d6.right().unwrap().internal_ref();

        assert_eq!(i.right().unwrap().leaf_ref(), &Leaf::new("Aaron", 0x03, 0));
        assert_eq!(d1.left(), None);
        assert_eq!(d2.left(), None);
        assert_eq!(d3.right(), None);
        assert_eq!(d4.right(), None);
        assert_eq!(d5.right(), None);
        assert_eq!(d6.left(), None);
        assert_eq!(d7.right().unwrap().leaf_ref(), &Leaf::new("Bob", 0x01, 5));
        assert_eq!(d7.left().unwrap().leaf_ref(), &Leaf::new("Charlie", 0x02, 5));
    }
}
