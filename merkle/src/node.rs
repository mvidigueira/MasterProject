use serde::{Deserialize, Serialize};

use drop::crypto::Digest;
use drop::crypto;

use std::rc::*;

pub trait Hashable {
    fn hash(&self) -> Digest;
}

impl Hashable for String {
    fn hash(&self) -> Digest {
        crypto::hash(&self).unwrap()
    }
}

pub trait Child<K, V> {
    fn parent(&self) -> Option<Rc<Node<K, V>>>
    where
        K: Serialize + Eq,
        V: Serialize;
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
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Internal<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    left: Option<Rc<Node<K, V>>>,
    right: Option<Rc<Node<K, V>>>,
    //#[serde(skip, default = "Option::default")]
    parent: Option<Weak<Node<K,V>>>,
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

impl<K, V> Child<K, V> for Internal<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    fn parent(&self) -> Option<Rc<Node<K, V>>> {
        match &self.parent {
            None => None,
            Some(w) => w.upgrade()
        }
    }
}

impl<K, V> Internal<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    fn new(left: Option<Rc<Node<K, V>>>, right: Option<Rc<Node<K, V>>>) -> Self {
        Internal{left, right, parent: None}
    }

    fn set_parent(&mut self, parent: &Rc<Node<K,V>>) {
        self.parent = Some(Rc::downgrade(parent));
    }

    fn remove_parent(&mut self) {
        self.parent = None;
    }

    fn left(&self) -> Option<&Rc<Node<K, V>>> {
        self.left.as_ref()
    }

    fn remove_left(&mut self) -> Option<Rc<Node<K,V>>> {
        self.left.take()
    }

    fn right(&self) -> Option<&Rc<Node<K, V>>> {
        self.right.as_ref()
    }

    fn remove_right(&mut self) -> Option<Rc<Node<K,V>>> {
        self.right.take()
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

    #[test]
    fn internal_constructor1() {
        let left_r  = Rc::new(Node::Leaf(Leaf::new("left" , 0x00)));
        let right_r = Rc::new(Node::Leaf(Leaf::new("right", 0x01)));
        let i = Internal::new(Some(left_r), Some(right_r));

        match (i.left.unwrap().as_ref(), i.right.unwrap().as_ref()) {
            (Node::Leaf(l), Node::Leaf(r)) => {
                assert_eq!(*l.key(), "left");
                assert_eq!(*l.value(), 0x00);
                assert_eq!(*r.key(), "right");
                assert_eq!(*r.value(), 0x01);
            },
            _ => panic!("One of the child nodes was not a leaf."),
        };
    }

    #[test]
    fn internal_constructor2() {
        let left_r  = Rc::new(Leaf::new("left" , 0x00).into());
        let right_r = Rc::new(Leaf::new("right", 0x01).into());
        let i1 = Internal::new(Some(left_r), Some(right_r));
        let i2 = Internal::new(Some(Rc::new(i1.into())), None);

        match (i2.left().unwrap().as_ref(), i2.right()) {
            (Node::Internal(i), None) => {
                match (i.left().unwrap().as_ref(), i.right().unwrap().as_ref()) {
                    (Node::Leaf(l), Node::Leaf(r)) => {
                        assert_eq!(*l.key(), "left");
                        assert_eq!(*l.value(), 0x00);
                        assert_eq!(*r.key(), "right");
                        assert_eq!(*r.value(), 0x01);
                    },
                    _ => panic!("One of the child nodes of the left internal node was not a leaf."),
                };
            },
            (_, Some(_)) => panic!("Right child not None"),
            _ => panic!("Wrong cast for children"),
        }
    }

    #[test]
    fn internal_hash_correctness1() {
        let left_r  = Rc::new(Leaf::new("left" , 0x00).into());
        let right_r = Rc::new(Leaf::new("right", 0x01).into());
        let i = Internal::new(Some(left_r), Some(right_r));
        let h1 = i.hash();
        let p1 = Internal::new(Some(Rc::new(i.into())), None);

        let left_r  = Rc::new(Leaf::new("left" , 0x00).into());
        let right_r = Rc::new(Leaf::new("right", 0x01).into());
        let i = Internal::new(Some(left_r), Some(right_r));
        let h2 = i.hash();
        let p2 = Internal::new(Some(Rc::new(i.into())), None);

        assert_eq!(h1, h2);
        assert_eq!(p1.hash(), p2.hash());

        
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
}
