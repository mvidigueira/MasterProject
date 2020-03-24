// TODO: REMOVE THIS LATER!
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use drop::crypto::{self, Digest};
use std::fmt;

// bits: 0 -> most significant, 255 -> least significant
#[inline]
pub fn bit(arr: &[u8; 32], index: u8) -> bool {
    let byte = arr[(index / 8) as usize];
    let sub_index: u8 = 1 << (7 - (index % 8));
    (byte & sub_index) > 0
}

pub trait Hashable {
    fn hash(&self) -> Digest;
}

impl Hashable for String {
    fn hash(&self) -> Digest {
        crypto::hash(&self).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum Node<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    Internal(Internal<K, V>),
    Placeholder(Placeholder),
    Leaf(Leaf<K, V>),
}

impl<K, V> Node<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
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

    fn is_placeholder(&self) -> bool {
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

    pub fn get(&self, k: K, depth: u32) -> Result<&V, &'static str> {
        let d = crypto::hash(&k).unwrap();
        self.get_internal(k, depth, &d)
    }

    /// Tries to return the value associated to key k from the underlying tree.
    /// k_digest must be the digest of k using `crypto::hash()`.
    /// depth is the depth of the current node in the tree (between 0 and 255).
    ///
    /// # Errors
    ///
    /// If the key association does not exist, or the key association is not present
    /// in the local structure, returns an error.
    /// ```
    fn get_internal(
        &self,
        k: K,
        depth: u32,
        k_digest: &Digest,
    ) -> Result<&V, &'static str> {
        match self {
            Node::Internal(n) => n.get_internal(k, depth, k_digest),
            Node::Placeholder(_) => {
                Err("key association not present in local tree (possibly behind placeholder)")
            }
            Node::Leaf(n) => n.get_internal(k),
        }
    }

    pub fn insert(self, k: K, v: V, depth: u32) -> Self {
        let d = crypto::hash(&k).unwrap();
        self.insert_internal(k, v, depth, &d)
    }

    /// Adds the key value (k, v) association to the underlying tree.
    /// k_digest must be the digest of k using `crypto::hash()`.
    /// depth is the depth of the current node in the tree (between 0 and 255).
    ///
    /// # Panics
    ///
    /// Behaviour is currently unspecified for the `Placeholder` variant,
    /// panicking with unimplemented!(...).
    /// Behaviour is currently unspecified if the key (k) is already present,
    /// panicking with unimplemented!(...)
    fn insert_internal(
        self,
        k: K,
        v: V,
        depth: u32,
        k_digest: &Digest,
    ) -> Self {
        match self {
            Node::Internal(n) => {
                n.insert_internal(k, v, depth, k_digest).into()
            }
            Node::Placeholder(_) => unimplemented!(
                "Unspecified behaviour for 'insert' on placeholder"
            ),
            Node::Leaf(n) => n.insert_internal(k, v, depth, k_digest).into(),
        }
    }

    pub fn remove(self, k: K, depth: u32) -> (Option<V>, Option<Self>) {
        let d = crypto::hash(&k).unwrap();
        self.remove_internal(k, depth, &d)
    }

    fn remove_internal(
        self,
        k: K,
        depth: u32,
        k_digest: &Digest,
    ) -> (Option<V>, Option<Self>) {
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
}

impl<K, V> Hashable for Node<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
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
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    fn from(l: Leaf<K, V>) -> Self {
        Node::Leaf(l)
    }
}

impl<K, V> From<Internal<K, V>> for Node<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    fn from(i: Internal<K, V>) -> Self {
        Node::Internal(i)
    }
}

impl<K, V> From<Placeholder> for Node<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    fn from(ph: Placeholder) -> Self {
        Node::Placeholder(ph)
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Copy, Clone)]
pub struct Leaf<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    k: K,
    v: V,
}

impl<K, V> Hashable for Leaf<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    fn hash(&self) -> Digest {
        crypto::hash(&self).unwrap()
    }
}

impl<K, V> Leaf<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    pub fn new(key: K, value: V) -> Self {
        Leaf { k: key, v: value }
    }

    pub fn key(&self) -> &K {
        &self.k
    }

    pub fn value(&self) -> &V {
        &self.v
    }

    fn get_internal(&self, k: K) -> Result<&V, &'static str> {
        if self.k == k {
            Ok(self.value())
        } else {
            Err("key association does not exist")
        }
    }

    fn insert_internal(
        self,
        k: K,
        v: V,
        depth: u32,
        k_digest: &Digest,
    ) -> Internal<K, V> {
        if self.k == k {
            unimplemented!("key value association already present");
        } else if depth == 255 {
            panic!("hash collision detected!");
        }

        let my_k = crypto::hash(&self.k).unwrap();

        let i = if bit(my_k.as_ref(), depth as u8) {
            Internal::new(None, Some(self.into()))
        } else {
            Internal::new(Some(self.into()), None)
        };

        i.insert_internal(k, v, depth, k_digest)
    }

    fn remove_internal(self, k: K) -> (Option<V>, Option<Self>) {
        if self.k == k {
            (Some(self.v), None)
        } else {
            (None, Some(self)) // consider refactoring (return an error)
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Internal<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    left: Option<Box<Node<K, V>>>,
    right: Option<Box<Node<K, V>>>,
}

impl<K, V> Hashable for Internal<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    fn hash(&self) -> Digest {
        if let (None, None) = (&self.left, &self.right) {
            panic!("Internal node must have at least one child.")
        }

        let default_hash = crypto::hash(&0).unwrap();
        let left_h = match &self.left {
            Some(x) => x.as_ref().hash(),
            None => default_hash,
        };
        let right_h = match &self.right {
            Some(x) => x.as_ref().hash(),
            None => default_hash,
        };

        crypto::hash(&(left_h, right_h)).unwrap()
    }
}

impl<K, V> Internal<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
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
        let i = Internal { left, right };
        i
    }

    pub fn left(&self) -> Option<&Node<K, V>> {
        match &self.left {
            None => None,
            Some(b) => Some(b.as_ref()),
        }
    }

    pub fn right(&self) -> Option<&Node<K, V>> {
        match &self.right {
            None => None,
            Some(b) => Some(b.as_ref()),
        }
    }

    fn get_internal(
        &self,
        k: K,
        depth: u32,
        k_digest: &Digest,
    ) -> Result<&V, &'static str> {
        if bit(k_digest.as_ref(), depth as u8) {
            match &self.right {
                Some(n) => n.as_ref().get_internal(k, depth + 1, k_digest),
                None => Err("key association does not exist"),
            }
        } else {
            match &self.left {
                Some(n) => n.as_ref().get_internal(k, depth + 1, k_digest),
                None => Err("key association does not exist"),
            }
        }
    }

    fn insert_internal(
        mut self,
        k: K,
        v: V,
        depth: u32,
        k_digest: &Digest,
    ) -> Self {
        if bit(k_digest.as_ref(), depth as u8) {
            self.right = match self.right {
                None => Some(Box::new(Leaf::new(k, v).into())),
                Some(n) => {
                    Some(Box::new(n.insert_internal(k, v, depth + 1, k_digest)))
                }
            }
        } else {
            self.left = match self.left {
                None => Some(Box::new(Leaf::new(k, v).into())),
                Some(n) => {
                    Some(Box::new(n.insert_internal(k, v, depth + 1, k_digest)))
                }
            }
        };

        self
    }

    fn remove_internal(
        mut self,
        k: K,
        depth: u32,
        k_digest: &Digest,
    ) -> (Option<V>, Node<K, V>) {
        if bit(k_digest.as_ref(), depth as u8) {
            if self.right.is_none() {
                return (None, self.into());
            }
            let r = self.right.unwrap().remove_internal(k, depth + 1, k_digest);
            self.right = match r.1 {
                Some(a) => Some(Box::new(a)),
                None => None,
            };

            match (&self.left, &self.right) {
                (None, None) => panic!("Impossible"),
                (Some(n), None) if !n.is_internal() => {
                    return (r.0, *self.left.unwrap())
                }
                (None, Some(n)) if !n.is_internal() => {
                    return (r.0, *self.right.unwrap())
                }
                _ => (r.0, self.into()),
            }
        } else {
            if self.left.is_none() {
                return (None, self.into());
            }
            let r = self.left.unwrap().remove_internal(k, depth + 1, k_digest);
            self.left = match r.1 {
                Some(a) => Some(Box::new(a)),
                None => None,
            };

            match (&self.left, &self.right) {
                (None, None) => panic!("Impossible"),
                (Some(n), None) if !n.is_internal() => {
                    return (r.0, *self.left.unwrap())
                }
                (None, Some(n)) if !n.is_internal() => {
                    return (r.0, *self.right.unwrap())
                }
                _ => (r.0, self.into()),
            }
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Copy)]
pub struct Placeholder {
    d: Digest,
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
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    fn from(l: Leaf<K, V>) -> Self {
        Placeholder { d: l.hash() }
    }
}

impl<K, V> From<Internal<K, V>> for Placeholder
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    fn from(i: Internal<K, V>) -> Self {
        Placeholder { d: i.hash() }
    }
}

impl<K, V> From<&Node<K, V>> for Placeholder
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    fn from(n: &Node<K, V>) -> Self {
        Placeholder { d: n.hash() }
    }
}

impl<K, V> From<Node<K, V>> for Placeholder
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    fn from(n: Node<K, V>) -> Self {
        match n {
            Node::Placeholder(n) => n,
            a => a.into(),
        }
    }
}

// MERKLE PROOFs

impl<K, V> Node<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    #![allow(dead_code)]
    pub fn get_proof_single_internal(
        &self,
        key: K,
        depth: u32,
        k_digest: &Digest,
    ) -> Result<Self, &'static str> {
        match self {
            Node::Internal(n) => match n.get_proof_single_internal(key, depth, k_digest) {
                Ok(n) => Ok(n.into()),
                Err(e) => Err(e),
            },
            Node::Placeholder(_) => {
                Err("Unspecified behaviour for 'get_proof_single_internal' for Placeholder")
            }
            Node::Leaf(n) => match n.get_proof_single_internal(key) {
                Ok(n) => Ok(n.into()),
                Err(e) => Err(e),
            },
        }
    }
}

impl<K, V> Leaf<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    #![allow(dead_code)]
    pub fn get_proof_single_internal(
        &self,
        key: K,
    ) -> Result<Self, &'static str> {
        if self.k == key {
            Ok(self.clone())
        } else {
            Err("attempting to get proof for non existing key association")
        }
    }
}

impl<K, V> Internal<K, V>
where
    K: Serialize + Copy + Eq,
    V: Serialize + Copy,
{
    #![allow(dead_code)]
    pub fn get_proof_single_internal(
        &self,
        k: K,
        depth: u32,
        k_digest: &Digest,
    ) -> Result<Self, &'static str> {
        if bit(k_digest.as_ref(), depth as u8) {
            let right = match &self.right {
                Some(n) => match n.as_ref().get_proof_single_internal(k, depth + 1, k_digest) {
                    Err(e) => { return Err(e); },
                    Ok(n) => Some(n),
                }
                None => { return Err("attempting to get proof for non existing key association"); },
            };
            let left = match &self.left {
                None => None,
                Some(n) => Some(Placeholder::new(n.hash()).into()),
            };
            Ok(Internal::new(left, right))
        } else {
            let left = match &self.left {
                Some(n) => match n.as_ref().get_proof_single_internal(k, depth + 1, k_digest) {
                    Err(e) => { return Err(e); },
                    Ok(n) => Some(n),
                }
                None => { return Err("attempting to get proof for non existing key association"); },
            };
            let right = match &self.right {
                None => None,
                Some(n) => Some(Placeholder::new(n.hash()).into()),
            };
            Ok(Internal::new(left, right))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn test_bit() {
        let u = &mut [0 as u8; 32];
        u[0] = 0x88;
        u[1] = 0x55;

        assert_eq!(bit(u, 0), true);
        assert_eq!(bit(u, 1), false);
        assert_eq!(bit(u, 8), false);
        assert_eq!(bit(u, 9), true);
    }

    macro_rules! h2d {
        ($data:expr) => {
            Digest::try_from($data).expect("failed to create digest")
        };
    }

    // CONSTRUCTOR TESTS

    #[test]
    fn leaf_constructor() {
        let l = Leaf::new("Test", 3);
        assert_eq!(l.k, "Test");
        assert_eq!(l.v, 3);
    }

    #[test]
    fn internal_constructor1() {
        let left_r = Leaf::new("left", 0x00).into();
        let right_r = Leaf::new("right", 0x01).into();
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
        let left_r = Leaf::new("left", 0x00).into();
        let right_r = Leaf::new("right", 0x01).into();
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
        let base = Leaf::new("", 0x00);
        let hash = base.hash();

        let ph: Placeholder = base.into();
        assert_eq!(ph.d, hash);
    }

    #[test]
    fn placeholder_from_internal() {
        let base = Leaf::new("", 0x00);
        let i = Internal::new(None, Some(base.into()));
        let hash = i.hash();

        let ph: Placeholder = i.into();
        assert_eq!(ph.d, hash);
    }

    // HASH CORRECTNESS TESTS

    #[test]
    fn leaf_hash() {
        let base = Leaf::new("", 0x00);

        let r1 = Leaf::new("", 0x01);
        assert_ne!(base.hash(), r1.hash());

        let r2 = Leaf::new("", 0x00);
        assert_eq!(base.hash(), r2.hash());

        let v: [u8; 0] = [];
        let r3 = Leaf::new("", v);
        assert_ne!(base.hash(), r3.hash());
    }

    #[test]
    fn internal_hash_correctness1() {
        let left_r = Leaf::new("left", 0x00).into();
        let right_r = Leaf::new("right", 0x01).into();
        let i = Internal::new(Some(left_r), Some(right_r));
        let h1 = i.hash();
        let p1 = Internal::new(Some(i.into()), None);

        let left_r = Leaf::new("left", 0x00).into();
        let right_r = Leaf::new("right", 0x01).into();
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
        let base = Leaf::new("Alice", 0x00);

        let v = base.get_internal("Alice").unwrap();
        assert_eq!(*v, 0x00);
    }

    #[test]
    #[should_panic(expected = "key association does not exist")]
    fn leaf_get_err_non_existant() {
        let base = Leaf::new("Alice", 0x00);

        base.get_internal("Bob").unwrap();
    }

    #[test]
    fn internal_get_normal() {
        let i: Node<_, _> = Internal::new(None, None).into();
        let i = i.insert("Alice", 0x01, 0);
        let i = i.insert("Bob", 0x02, 0);

        let v = i.get("Alice", 0).unwrap();
        assert_eq!(*v, 0x01);

        let v = i.get("Bob", 0).unwrap();
        assert_eq!(*v, 0x02);
    }

    #[test]
    #[should_panic(expected = "key association does not exist")]
    fn internal_get_err_non_existant() {
        let i: Node<_, _> = Internal::new(None, None).into();
        let i = i.insert("Alice", 0x01, 0);
        let i = i.insert("Bob", 0x02, 0);

        i.get("Charlie", 0).unwrap();
    }

    #[test]
    #[should_panic(expected = "key association not present in local tree")]
    fn internal_get_err_behind_placeholder() {
        let i: Node<_, _> = Internal::new(None, None).into();
        let i = i.insert("Bob", 0x01, 0); // left
        let i = i.insert("Aaron", 0x02, 0); // right, left
        let mut i = i.insert("Dave", 0x03, 0).internal(); // right, right

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

        let leaf = Leaf::new(leaf_k, 0x00);

        let k = "Bob";
        let digest = crypto::hash(&k).unwrap();
        assert_eq!(
            digest,
            h2d!("63688fc040203caed5265b7c08f5a5627ba260c2004ed1241fa859dd02160f54")
        );

        assert_eq!(bit(digest.as_ref(), 0), false);
        assert_eq!(bit(leaf_d.as_ref(), 0), true);

        let depth = 0;
        let i = leaf.insert_internal(k, 0x01, depth, &digest);

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

        let leaf = Leaf::new(leaf_k, 0x00);

        let k = "Aaron";
        let digest = crypto::hash(&k).unwrap();
        assert_eq!(
            digest,
            h2d!("82464cbbaaf39d3d5f924f44c09feccd921816359abf54a4dcb97aa54ef94c04")
        );

        let depth = 0;
        let i = leaf.insert_internal(k, 0x01, depth, &digest);

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

        let leaf = Leaf::new(leaf_k, 0x00);

        let k = "Bob";
        let digest = crypto::hash(&k).unwrap();
        assert_eq!(
            digest,
            h2d!("63688fc040203caed5265b7c08f5a5627ba260c2004ed1241fa859dd02160f54")
        );

        let depth = 0;
        let i: Node<_, _> = Internal::new(None, Some(leaf.into())).into();
        let i = i.insert(k, 0x01, depth).internal();

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

        let leaf = Leaf::new(leaf_k, 0x00);

        let k = "Aaron";
        let digest = crypto::hash(&k).unwrap();
        assert_eq!(
            digest,
            h2d!("82464cbbaaf39d3d5f924f44c09feccd921816359abf54a4dcb97aa54ef94c04")
        );

        let depth = 0;
        let i: Node<_, _> = Internal::new(None, Some(leaf.into())).into();
        let i = i.insert(k, 0x01, depth).internal();

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

    // REMOVE TESTS

    #[test]
    fn leaf_remove_normal() {
        let l: Node<_, _> = Leaf::new("Alice", 0x01).into();
        let v = l.remove("Alice", 0);
        assert_eq!(v.0, Some(0x01));
        if let Some(_) = v.1 {
            panic!("should return None for node");
        }
    }

    #[test]
    fn leaf_remove_non_existant() {
        let l: Node<_, _> = Leaf::new("Alice", 0x01).into();
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
        let i = i.insert("Bob", 0x01, 0); // left
        let i = i.insert("Aaron", 0x02, 0); // right

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
        let i = i.insert("Bob", 0x01, 0); // left
        let i = i.insert("Aaron", 0x02, 0); // right, left
        let i = i.insert("Dave", 0x03, 0); // right, right

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
        let i = i.insert("Bob", 0x02, 0); // L,R,R,L,L,L,R,R
        let i = i.insert("Charlie", 0x03, 0); // L,R,R,L,L,L,R,L

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
        let i = i.insert("Aaron", 0x01, 0); // right
        let i = i.insert("Bob", 0x02, 0); // L,R,R,L,L,L,R,R
        let i = i.insert("Charlie", 0x03, 0); // L,R,R,L,L,L,R,L

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
        let i = i.insert("Aaron", 0x01, 0); // right
        let i = i.insert("Bob", 0x02, 0); // L,R,R,L,L,L,R,R
        let i = i.insert("Charlie", 0x03, 0); // L,R,R,L,L,L,R,L

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
        let i: Node<_, _> = Leaf::new("Bob", 0x02).into(); // L,R,R,L,L,L,R,R
        let i = i.insert("Charlie", 0x03, 0); // L,R,R,L,L,L,R,L

        extern crate bincode;

        let ser = bincode::serialize(&i).unwrap();
        let g: Node<&str, i32> = bincode::deserialize(&ser).unwrap();

        assert_eq!(g.get("Bob", 0), Ok(&0x02));
        assert_eq!(g.get("Charlie", 0), Ok(&0x03));
    }

    // PROOF TESTS

    #[test]
    fn leaf_get_proof_single() -> Result<(), &'static str> {
        let l = Leaf::new("Alice", 1);
        let a = l.get_proof_single_internal("Alice")?;

        assert_eq!(*a.value(), 1);
        assert_eq!(*a.key(), "Alice");

        Ok(())
    }

    #[test]
    #[should_panic(expected = "attempting to get proof for non existing key association")]
    fn leaf_get_proof_single_err() {
        let l = Leaf::new("Alice", 1);
        l.get_proof_single_internal("Bob").unwrap();
    }

    #[test]
    fn internal_get_proof_single1() {
        let l: Node<_, _> = Leaf::new("Bob", 1).into(); //left
        let i = l.insert("Aaron", 2, 0); //right

        let h = crypto::hash(&"Aaron").unwrap();
        let proof = i
            .get_proof_single_internal("Aaron", 0, &h)
            .unwrap()
            .internal();

        let ph: Placeholder = Leaf::new("Bob", 1).into();

        assert_eq!(*proof.left().unwrap().placeholder_ref(), ph);
        assert_eq!(*proof.right().unwrap().leaf_ref(), Leaf::new("Aaron", 2));
    }

    #[test]
    fn internal_get_proof_single2() {
        let l: Node<_, _> = Leaf::new("Bob", 0x01).into(); //left
        let i = l.insert("Aaron", 0x02, 0); //right, left
        let i = i.insert("Dave", 0x03, 0); // right, right

        let h = crypto::hash(&"Dave").unwrap();
        let proof = i
            .get_proof_single_internal("Dave", 0, &h)
            .unwrap()
            .internal();

        let ph_bob: Placeholder = Leaf::new("Bob", 0x01).into();
        let ph_aar: Placeholder = Leaf::new("Aaron", 0x02).into();

        let r1 = proof.right().unwrap().internal_ref();

        assert_eq!(*proof.left().unwrap().placeholder_ref(), ph_bob);
        assert_eq!(*r1.left().unwrap().placeholder_ref(), ph_aar);
        assert_eq!(*r1.right().unwrap().leaf_ref(), Leaf::new("Dave", 0x03));
    }

    #[test]
    fn internal_get_proof_single3() {
        let l: Node<_, _> = Leaf::new("Bob", 0x01).into(); // L,R,R,L,L,L,R,R
        let i = l.insert("Charlie", 0x03, 0); // L,R,R,L,L,L,R,L
        let i = i.insert("Aaron", 0x02, 0); // right (R)

        let h = crypto::hash(&"Charlie").unwrap();
        let proof = i
            .get_proof_single_internal("Charlie", 0, &h)
            .unwrap()
            .internal();

        let ph_bob: Placeholder = Leaf::new("Bob", 0x01).into();
        let ph_aar: Placeholder = Leaf::new("Aaron", 0x02).into();

        let d1 = proof.left().unwrap().internal_ref();
        let d2 = d1.right().unwrap().internal_ref();
        let d3 = d2.right().unwrap().internal_ref();
        let d4 = d3.left().unwrap().internal_ref();
        let d5 = d4.left().unwrap().internal_ref();
        let d6 = d5.left().unwrap().internal_ref();
        let d7 = d6.right().unwrap().internal_ref();

        assert_eq!(*proof.right().unwrap().placeholder_ref(), ph_aar);
        assert!(d1.left().is_none());
        assert!(d2.left().is_none());
        assert!(d3.right().is_none());
        assert!(d4.right().is_none());
        assert!(d5.right().is_none());
        assert!(d6.left().is_none());
        assert_eq!(*d7.right().unwrap().placeholder_ref(), ph_bob);
        assert_eq!(*d7.left().unwrap().leaf_ref(), Leaf::new("Charlie", 0x03));
    }
}
