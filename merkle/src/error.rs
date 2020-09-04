use std::{error::Error, fmt};
use drop::crypto::Digest;

#[derive(Debug, Eq, PartialEq)]
pub enum MerkleError {
    KeyBehindPlaceholder(Digest),
    KeyNonExistant,
    IncompatibleTrees,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MerkleError::KeyBehindPlaceholder(ph) =>
                write!(f, "key association not present in local tree. Behind placeholder: {}", ph),
            MerkleError::KeyNonExistant =>
                write!(f, "key association does not exist"),
            MerkleError::IncompatibleTrees =>
                write!(f, "the merkle trees are incompatible (different hashes)"),
        }
    }
}

impl Error for MerkleError {}