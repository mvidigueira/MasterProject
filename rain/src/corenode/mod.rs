mod corenode;
mod memory_usage;
mod error;
mod comm_structs;
mod history_tree;
mod prefix;

#[cfg(test)]
pub mod test;

use prefix::Prefix;

pub use corenode::CoreNode;
pub use corenode::Info as CoreNodeInfo;
pub use history_tree::HistoryTree;
pub use prefix::SystemConfig;
pub use error::CoreNodeError;

pub use comm_structs::{UserCoreRequest, UserCoreResponse, TobRequest, TobResponse, BlsSigInfo, BlsSigWrapper, ExecuteResult, PayloadForTob, Touch, RuleTransaction, get_misc_digest};

use drop::crypto::Digest;

pub use bls_amcl::common::{Keypair as BlsKeypair, Params as BlsParams, SigKey as BlsSigKey, VerKey as BlsVerKey};
pub use bls_amcl::multi_sig_fast::{AggregatedVerKeyFast as BlsVerifySignatures, MultiSignatureFast as BlsAggregateSignatures};
pub use bls_amcl::simple::Signature as BlsSignature;

use merkle::Tree;

pub type RecordID = String;
pub type RecordVal = Vec<u8>;
pub type DataTree = Tree<RecordID, RecordVal>;
pub type HTree = HistoryTree<RecordID, RecordVal>;

