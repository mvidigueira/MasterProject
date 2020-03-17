use serde::{Deserialize, Serialize};

use drop::crypto::Digest;
use drop::crypto;

// bits: 0 -> most significant, 255 -> least significant
fn bit(arr: &[u8; 32], index: u8) -> bool {
    let byte = arr[(index/8) as usize];
    let sub_index: u8 =  1 << (7 - (index % 8));
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

#[derive(Serialize, Deserialize, Debug)]
pub enum Node<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    Internal(Internal<K, V>),
    Placeholder(Placeholder),
    Leaf(Leaf<K, V>),
}

impl<K, V> Node<K, V> 
where
    K: Serialize + Eq,
    V: Serialize,
{
    fn leaf(self) -> Leaf<K, V> {
        match self {
            Node::Leaf(n) => n,
            _ => panic!("not a leaf node"),
        }
    }

    fn internal(self) -> Internal<K, V> {
        match self {
            Node::Internal(n) => n,
            _ => panic!("not an internal node"),
        }
    }

    fn placeholder(self) -> Placeholder {
        match self {
            Node::Placeholder(n) => n,
            _ => panic!("not a placeholder node"),
        }
    }

    fn add_internal(self, k: K, v: V, k_digest: &Digest, depth: u32) -> Self {
        match self {
            Node::Internal(n) => n.add_internal(k, v, k_digest, depth).into(),
            Node::Placeholder(_) => unimplemented!("Unspecified behaviour for 'add' on placeholder"),
            Node::Leaf(n) => n.add_internal(k, v, k_digest, depth).into(),
        }
    }
}

impl<K, V> Hashable for Node<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
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
    K: Serialize + Eq,
    V: Serialize,
{
    fn from(l: Leaf<K, V>) -> Self {
        Node::Leaf(l)
    }
}

impl<K, V> From<Internal<K, V>> for Node<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    fn from(i: Internal<K, V>) -> Self {
        Node::Internal(i)
    }
}

impl<K, V> From<Placeholder> for Node<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    fn from(ph: Placeholder) -> Self {
        Node::Placeholder(ph)
    }
}

#[derive(Serialize, Deserialize, Debug)]
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
    K: Serialize + Eq,
    V: Serialize,
{
    fn hash(&self) -> Digest {
        crypto::hash(&self).unwrap()
    }
}

impl<K, V> Leaf<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
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

    fn add_internal(mut self, k: K, v: V, k_digest: &Digest, depth: u32) -> Internal<K,V> {
        if self.k == k {
            unimplemented!("Key value association already present");
        } else if depth == 255 {
            panic!("Hash collision detected!");
        }

        let my_k = crypto::hash(&self.k).unwrap();
        
        let i = if bit(my_k.as_ref(), depth as u8) {
            Internal::new(None, Some(self.into()))
        } else {
            Internal::new(Some(self.into()), None)
        };
        
        i.add_internal(k, v, k_digest, depth)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Internal<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    left: Option<Box<Node<K, V>>>,
    right: Option<Box<Node<K, V>>>,
}

impl<K, V> Hashable for Internal<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
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
    K: Serialize + Eq,
    V: Serialize,
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
        let i = Internal{left, right};
        i
    }

    fn left(&self) -> Option<&Node<K, V>> {
        match &self.left {
            None => None,
            Some(b) => Some(b.as_ref())
        }
    }

    fn remove_left(&mut self) -> Option<Box<Node<K,V>>> {
        self.left.take()
    }

    fn right(&self) -> Option<&Node<K, V>> {
        match &self.right {
            None => None,
            Some(b) => Some(b.as_ref())
        }
    }

    fn remove_right(&mut self) -> Option<Box<Node<K,V>>> {
        self.right.take()
    }

    fn add_internal(mut self, k: K, v: V, k_digest: &Digest, depth: u32) -> Internal<K,V> {
        if bit(k_digest.as_ref(), depth as u8) {
            self.right = match self.right {
                None => Some(Box::new(Leaf::new(k, v).into())),
                Some(n) => Some(Box::new(n.add_internal(k, v, k_digest, depth + 1))),
            }
        } else {
            self.left = match self.left {
                None => Some(Box::new(Leaf::new(k, v).into())),
                Some(n) => Some(Box::new(n.add_internal(k, v, k_digest, depth + 1))),
            }
        };

        self
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Placeholder {
    d: Digest,
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
    K: Serialize + Eq,
    V: Serialize,
{
    fn from(l: Leaf<K, V>) -> Self {
        Placeholder { d: l.hash() }
    }
}

impl<K, V> From<Internal<K, V>> for Placeholder
where
    K: Serialize + Eq,
    V: Serialize,
{
    fn from(l: Internal<K, V>) -> Self {
        Placeholder { d: l.hash() }
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

        // bits: 0 -> most significant, 255 -> least significant
        // fn bit(arr: &[u8; 32], index: u8) -> bool {
        //     let byte = arr[(index/32) as usize];
        //     let sub_index: u8 =  2^(7-(index % 8));
        //     (byte & sub_index) > 0
        // }


    }

    macro_rules! h2d {
        ($data:expr) => {
            Digest::try_from($data).expect("failed to create digest")
        }
    }

    #[test]
    fn leaf_constructor() {
        let l = Leaf::new("Test".to_string(), 3);
        assert_eq!(l.k, "Test".to_string());
        assert_eq!(l.v, 3);
    }

    #[test]
    fn leaf_hash() {
        let base = Leaf::new("".to_string(), 0x00);

        let r1 = Leaf::new("".to_string(), 0x01);
        assert_ne!(base.hash(), r1.hash());

        let r2 = Leaf::new("".to_string(), 0x00);
        assert_eq!(base.hash(), r2.hash());

        let v: [u8; 0] = [];
        let r3 = Leaf::new("".to_string(), v);
        assert_ne!(base.hash(), r3.hash());
    }

    // Initially there is only one leaf which key hash starts with b1...
    // We add (k,v) such that hash(k) starts with b0...
    // The addition should therefore return an Internal node with children:
    //  - left:     Leaf(k,v)
    //  - right:    original leaf node
    #[test]
    fn leaf_add1() {
        let leaf_k = "left".to_string();
        let leaf_d = crypto::hash(&leaf_k).unwrap();
        assert_eq!(leaf_d, h2d!("c8c3fff091d468a9c3d758eb79f31b0e9cef2718681b81ec693d0990a639962f"));

        let leaf = Leaf::new(leaf_k, 0x00);

        let k = "Bob".to_string();
        let digest = crypto::hash(&k).unwrap();
        assert_eq!(digest, h2d!("63688fc040203caed5265b7c08f5a5627ba260c2004ed1241fa859dd02160f54"));

        assert_eq!(bit(digest.as_ref(), 0), false);
        assert_eq!(bit(leaf_d.as_ref(), 0), true);

        let depth = 0;
        let i = leaf.add_internal(k, 0x01, &digest, depth);

        println!("{:?}", i);

        if let Node::Leaf(l) = i.left().expect("missing left node") {
            assert_eq!(l.k, "Bob".to_string());
            assert_eq!(l.v, 0x01);
        } else {
            panic!("left node not leaf");
        }

        if let Node::Leaf(r) = i.right().expect("missing right node") {
            assert_eq!(r.k, "left".to_string());
            assert_eq!(r.v, 0x00);
        } else {
            panic!("right node not leaf");
        }
    }

    // Initially there is only one leaf which key hash starts with b11...
    // We add (k,v) such that hash(k) starts with b10...
    // The addition should therefore return an Internal node with children:
    //  - left:     None
    //  - right:    Internal
    //      -- left:    Leaf(k,v)
    //      -- right:   original leaf node
    #[test]
    fn leaf_add2() {
        let leaf_k = "left".to_string();
        let leaf_d = crypto::hash(&leaf_k).unwrap();
        assert_eq!(leaf_d, h2d!("c8c3fff091d468a9c3d758eb79f31b0e9cef2718681b81ec693d0990a639962f"));

        let leaf = Leaf::new(leaf_k, 0x00);

        let k = "Aaron".to_string();
        let digest = crypto::hash(&k).unwrap();
        assert_eq!(digest, h2d!("82464cbbaaf39d3d5f924f44c09feccd921816359abf54a4dcb97aa54ef94c04"));

        let depth = 0;
        let i = leaf.add_internal(k, 0x01, &digest, depth);

        if let Some(_) = i.left() {
            panic!("left of depth 0 internal node should be empty");
        }

        if let Some(Node::Internal(i)) = i.right() {
            if let Node::Leaf(l) = i.left().expect("missing left node of depth 1 internal node") {
                assert_eq!(l.k, "Aaron".to_string());
                assert_eq!(l.v, 0x01);
            } else {
                panic!("left node of depth 1 internal node not a leaf");
            }

            if let Node::Leaf(r) = i.right().expect("missing right node of depth 1 internal node") {
                assert_eq!(r.k, "left".to_string());
                assert_eq!(r.v, 0x00);
            } else {
                panic!("right node of depth 1 internal node not a leaf");
            }
        }
    }

    #[test]
    fn internal_constructor1() {
        let left_r  = Leaf::new("left" , 0x00).into();
        let right_r = Leaf::new("right", 0x01).into();
        let i = Internal::new(Some(left_r), Some(right_r));

        match (i.left.unwrap().as_ref(), i.right.unwrap().as_ref()) {
            (Node::Leaf(l), Node::Leaf(r)) => {
                assert_eq!(*l.key(), "left");
                assert_eq!(*l.value(), 0x00);
                assert_eq!(*r.key(), "right");
                assert_eq!(*r.value(), 0x01);
            },
            _ => panic!("one of the child nodes was not a leaf"),
        };
    }

    #[test]
    fn internal_constructor2() {
        let left_r  = Leaf::new("left" , 0x00).into();
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
                    },
                    _ => panic!("one of the child nodes of the left internal node was not a leaf"),
                };
            },
            (_, Some(_)) => panic!("right child not None"),
            _ => panic!("wrong cast for children"),
        }
    }

    #[test]
    fn internal_hash_correctness1() {
        let left_r  = Leaf::new("left" , 0x00).into();
        let right_r = Leaf::new("right", 0x01).into();
        let i = Internal::new(Some(left_r), Some(right_r));
        let h1 = i.hash();
        let p1 = Internal::new(Some(i.into()), None);

        let left_r  = Leaf::new("left" , 0x00).into();
        let right_r = Leaf::new("right", 0x01).into();
        let i = Internal::new(Some(left_r), Some(right_r));
        let h2 = i.hash();
        let p2 = Internal::new(Some(i.into()), None);

        assert_eq!(h1, h2);
        assert_eq!(p1.hash(), p2.hash());
    }

    // Initially there is only one internal node holding a leaf which key hash starts with b1...
    // We add (k,v) such that hash(k) starts with b0...
    // The addition should therefore return nothing.
    // The Internal node should end with children:
    //  - left:     Leaf(k,v)
    //  - right:    original leaf node
    #[test]
    fn internal_add1() {
        let leaf_k = "left".to_string();
        let leaf_d = crypto::hash(&leaf_k).unwrap();
        assert_eq!(leaf_d, h2d!("c8c3fff091d468a9c3d758eb79f31b0e9cef2718681b81ec693d0990a639962f"));

        let leaf = Leaf::new(leaf_k, 0x00);

        let k = "Bob".to_string();
        let digest = crypto::hash(&k).unwrap();
        assert_eq!(digest, h2d!("63688fc040203caed5265b7c08f5a5627ba260c2004ed1241fa859dd02160f54"));

        let depth = 0;
        let i = Internal::new(None, Some(leaf.into()));
        let i = i.add_internal(k, 0x01, &digest, depth);

        if let Node::Leaf(l) = i.left().expect("missing left node") {
            assert_eq!(l.k, "Bob".to_string());
            assert_eq!(l.v, 0x01);
        } else {
            panic!("left node not leaf");
        }

        if let Node::Leaf(r) = i.right().expect("missing left node") {
            assert_eq!(r.k, "left".to_string());
            assert_eq!(r.v, 0x00);
        } else {
            panic!("right node not a leaf");
        }
    }

    // Initially there is only one leaf which key hash starts with b11...
    // We add (k,v) such that hash(k) starts with b10...
    // The addition should therefore return nothing.
    // The Internal node should end with children:
    //  - left:     None
    //  - right:    Internal
    //      -- left:    Leaf(k,v)
    //      -- right:   original leaf node
    #[test]
    fn internal_add2() {
        let leaf_k = "left".to_string();
        let leaf_d = crypto::hash(&leaf_k).unwrap();
        assert_eq!(leaf_d, h2d!("c8c3fff091d468a9c3d758eb79f31b0e9cef2718681b81ec693d0990a639962f"));

        let leaf = Leaf::new(leaf_k, 0x00);

        let k = "Aaron".to_string();
        let digest = crypto::hash(&k).unwrap();
        assert_eq!(digest, h2d!("82464cbbaaf39d3d5f924f44c09feccd921816359abf54a4dcb97aa54ef94c04"));

        let depth = 0;
        let i = Internal::new(None, Some(leaf.into()));
        let i: Internal<_,_> = i.add_internal(k, 0x01, &digest, depth);

        if let Some(Node::Internal(i)) = i.right() {
            if let Node::Leaf(l) = i.left().expect("missing left node of depth 1 internal node") {
                assert_eq!(l.k, "Aaron".to_string());
                assert_eq!(l.v, 0x01);
            } else {
                panic!("left node of depth 1 internal node not a leaf");
            }

            if let Node::Leaf(r) = i.right().expect("missing right node of depth 1 internal node") {
                assert_eq!(r.k, "left".to_string());
                assert_eq!(r.v, 0x00);
            } else {
                panic!("right node of depth 1 internal node not a leaf");
            }
        }
    }

    macro_rules! test_hash {
        ($data:expr) => {
            crypto::hash(&($data)).expect("failed to hash data")
        }
    }

    #[test]
    fn placeholder_constructor() {
        let ph = Placeholder::new(test_hash!(0u32));

        assert_eq!(ph.hash(), test_hash!(0u32));
        assert_eq!(ph.d, test_hash!(0u32));
    }

    #[test]
    fn placeholder_from_leaf() {
        let base = Leaf::new("".to_string(), 0x00);
        let hash = base.hash();

        let ph: Placeholder = base.into();
        assert_eq!(ph.d, hash);
    }

    #[test]
    fn placeholder_from_internal() {
        let base = Leaf::new("".to_string(), 0x00);
        let i = Internal::new(None, Some(base.into()));
        let hash = i.hash();

        let ph: Placeholder = i.into();
        assert_eq!(ph.d, hash);
    }
}
