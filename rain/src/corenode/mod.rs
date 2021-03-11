mod comm_structs;
mod corenode;
mod error;
mod history_tree;
mod memory_usage;
mod prefix;

use drop::crypto::Digest;

pub use corenode::CoreNode;
pub use corenode::Info as CoreNodeInfo;
pub use error::CoreNodeError;
pub use history_tree::HistoryTree;
pub use prefix::Prefix;
pub use prefix::SystemConfig;

pub use comm_structs::{
    get_misc_digest, BlsSigInfo, BlsSigWrapper, ExecuteResult, PayloadForTob,
    RuleTransaction, TobRequest, Touch, UserCoreRequest,
    UserCoreResponse,
};

pub use bls_amcl::common::{
    Keypair as BlsKeypair, Params as BlsParams, SigKey as BlsSigKey,
    VerKey as BlsVerKey,
};
pub use bls_amcl::multi_sig_fast::{
    AggregatedVerKeyFast as BlsVerifySignatures,
    MultiSignatureFast as BlsAggregateSignatures,
};
pub use bls_amcl::simple::Signature as BlsSignature;

pub type RecordID = String;
pub type RecordVal = Vec<u8>;
pub type DataTree = merkle::Tree<RecordID, RecordVal>;
pub type HTree = HistoryTree<RecordID, RecordVal>;
