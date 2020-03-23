use crate::node::{Internal, Leaf, Node};
use drop::crypto::Digest;
use serde::Serialize;

impl<K, V> Node<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    #![allow(dead_code)]
    pub fn get_proof_single_internal(
        &self,
        key: K,
        depth: u32,
        k_digest: &Digest,
    ) -> Result<Self, &'static str> {
        unimplemented!();
    }
}

impl<K, V> Leaf<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    #![allow(dead_code)]
    pub fn get_proof_single_internal(
        &self,
        key: K,
    ) -> Result<Self, &'static str> {
        unimplemented!();
    }
}

impl<K, V> Internal<K, V>
where
    K: Serialize + Eq,
    V: Serialize,
{
    #![allow(dead_code)]
    pub fn get_proof_single_internal(
        &self,
        key: K,
        depth: u32,
        k_digest: &Digest,
    ) -> Result<Self, &'static str> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Placeholder;
    use drop::crypto;

    #[test]
    fn leaf_get_proof_single() -> Result<(), &'static str> {
        let l = Leaf::new("Alice", 1);
        let a = l.get_proof_single_internal("Alice")?;

        assert_eq!(*a.value(), 1);
        assert_eq!(*a.key(), "Alice");

        Ok(())
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
        assert_eq!(*r1.right().unwrap().leaf_ref(), Leaf::new("Dave", 2));
    }

    #[test]
    fn internal_get_proof_single3() {
        let l: Node<_, _> = Leaf::new("Bob", 0x01).into(); // left (x4), right
        let i = l.insert("Charlie", 0x03, 0); // left (x4), left
        let i = i.insert("Aaron", 0x02, 0); //right

        let h = crypto::hash(&"Charlie").unwrap();
        let proof = i
            .get_proof_single_internal("Charlie", 0, &h)
            .unwrap()
            .internal();

        let ph_bob: Placeholder = Leaf::new("Bob", 0x01).into();
        let ph_aar: Placeholder = Leaf::new("Aaron", 0x02).into();

        let l1 = proof.left().unwrap().internal_ref();
        let l2 = l1.left().unwrap().internal_ref();
        let l3 = l2.left().unwrap().internal_ref();
        let l4 = l3.left().unwrap().internal_ref();

        assert_eq!(*proof.right().unwrap().placeholder_ref(), ph_aar);
        assert!(l1.right().is_none());
        assert!(l2.right().is_none());
        assert!(l3.right().is_none());
        assert_eq!(*l4.right().unwrap().placeholder_ref(), ph_bob);
        assert_eq!(*l4.left().unwrap().leaf_ref(), Leaf::new("Charlie", 0x03));
    }
}
