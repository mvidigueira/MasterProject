use std::{error::Error, fmt};

#[derive(Debug, Eq, PartialEq)]
pub enum MerkleError {
    KeyBehindPlaceholder,
    KeyNonExistant,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MerkleError::KeyBehindPlaceholder =>
                write!(f, "key association not present in local tree (possibly behind placeholder)"),
            MerkleError::KeyNonExistant =>
                write!(f, "key association does not exist"),
        }
    }
}

impl Error for MerkleError {}
