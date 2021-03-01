mod error;

mod node;
mod tree;
mod util;

pub use tree::Tree;
pub use error::MerkleError;
pub use drop::crypto::hash;
pub use util::{get_is_close_fn, leading_bits_in_common, closest};
