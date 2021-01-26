mod client;
mod corenode;
mod module_cache;
mod memory_usage;

pub mod prefix;
pub mod history_tree;
pub mod simulated_contract;
mod tob_server;

#[cfg(test)]
pub mod test;

pub use client::ClientNode;
pub use corenode::CoreNode;
pub use tob_server::TobServer;
pub use prefix::Prefix;
pub use module_cache::{ModuleCache, ModuleCacheError};
use history_tree::HistoryTree;

use std::io::Error as IoError;

use drop::error::Error;
use drop::net::{
    ConnectError, ListenerError, ReceiveError, SendError,
};
use drop::crypto::Digest;

use merkle::{error::MerkleError, Tree};

use macros::error;
extern crate bincode;

error! {
    type: ReplyError,
    description: "reply does not follow protocol"
}

error! {
    type: InconsistencyError,
    description: "merkle trees are not consistent"
}

error! {
    type: ClientError,
    causes: (ConnectError, SendError, ReceiveError, ReplyError, MerkleError, InconsistencyError),
    description: "client failure"
}

error! {
    type: CoreNodeError,
    causes: (IoError, ListenerError, SendError, ReceiveError),
    description: "server failure"
}

error! {
    type: BroadcastError,
    description: "broadcast failure"
}

error! {
    type: TobServerError,
    causes: (IoError, ListenerError, SendError, BroadcastError),
    description: "server failure"
}

type RecordID = String;
type RecordVal = Vec<u8>;
type DataTree = Tree<RecordID, RecordVal>;
type HTree = HistoryTree<RecordID, RecordVal>;

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
enum UserCoreRequest {   // Request from User to Corenode
    GetProof(Vec<RecordID>),
    Execute(RuleTransaction),
}

impl From<Vec<RecordID>> for UserCoreRequest {
    fn from(v: Vec<RecordID>) -> Self {
        UserCoreRequest::GetProof(v)
    }
}

unsafe impl Send for UserCoreRequest {}
unsafe impl Sync for UserCoreRequest {}
impl classic::Message for UserCoreRequest {}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
enum UserCoreResponse {
    GetProof((usize, Tree<RecordID, RecordVal>)),
    Execute(ExecuteResult),
}

unsafe impl Send for UserCoreResponse {}
unsafe impl Sync for UserCoreResponse {}
impl classic::Message for UserCoreResponse {}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub struct ExecuteResult {
    rule_record_id: String,
    rule_version: Digest,
    output: Result<Vec<(RecordID, Touch)>, String>,
}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
enum Touch {
    Read,
    Deleted,
    Modified(RecordVal),
    Added(RecordVal),
}

impl ExecuteResult {
    pub fn new(
        rule_record_id: RecordID,
        rule_version: Digest,
        ledger: Vec<(RecordID, Touch)>,
    ) -> Self {
        Self {
            rule_record_id,
            rule_version,
            output: Ok(ledger),
        }
    }

    pub fn fail(
        rule_record_id: RecordID,
        rule_version: Digest,
        cause: String,
    ) -> Self {
        Self {
            rule_record_id,
            rule_version,
            output: Err(cause),
        }
    }
}


#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub struct RuleTransaction {
    merkle_proof: DataTree,
    rule_record_id: RecordID,
    rule_version: Digest,
    touched_records: Vec<RecordID>,
    rule_arguments: Vec<u8>,
}

impl RuleTransaction {
    pub fn new<T: classic::Serialize>(
        proof: DataTree,
        rule: RecordID,
        rule_digest: Digest,
        touched_records: Vec<RecordID>,
        args: &T,
    ) -> Self {
        Self {
            merkle_proof: proof,
            rule_record_id: rule,
            rule_version: rule_digest,
            touched_records: touched_records,
            rule_arguments: bincode::serialize(args).unwrap(),
        }
    }
}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub enum TobRequest {
    Apply(PayloadForTob),
}

unsafe impl Send for TobRequest {}
unsafe impl Sync for TobRequest {}
impl classic::Message for TobRequest {}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
struct PayloadForTob {
    rule_record_id: String,
    input_merkle_proof: DataTree,
    output: Vec<(RecordID, Touch)>,
}

impl PayloadForTob {
    pub fn new(
        rule_record_id: String,
        input_merkle_proof: DataTree,
        output: Vec<(RecordID, Touch)>
    ) -> Self {
        Self {
            rule_record_id,
            input_merkle_proof,
            output,
        }
    }
}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub enum TobResponse {
    Result(String),
}

unsafe impl Send for TobResponse {}
unsafe impl Sync for TobResponse {}
impl classic::Message for TobResponse {}
