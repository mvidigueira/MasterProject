mod client;
mod corenode;
pub mod history_tree;
pub mod simulated_contract;
mod tob_server;

#[cfg(test)]
pub mod test;

pub use client::ClientNode;
pub use corenode::CoreNode;
pub use tob_server::TobServer;
pub use history_tree::Prefix;

use std::io::Error as IoError;

use drop::error::Error;
use drop::net::{
    ConnectError, ListenerError, ReceiveError, SendError,
};

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

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
enum TxRequest {
    GetProof(Vec<RecordID>),
    Execute(RuleTransaction),
}

impl From<Vec<RecordID>> for TxRequest {
    fn from(v: Vec<RecordID>) -> Self {
        TxRequest::GetProof(v)
    }
}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
enum TxResponse {
    GetProof((usize, Tree<RecordID, RecordVal>)),
    Execute(String),
}

unsafe impl Send for TxRequest {}
unsafe impl Sync for TxRequest {}
impl classic::Message for TxRequest {}

unsafe impl Send for TxResponse {}
unsafe impl Sync for TxResponse {}
impl classic::Message for TxResponse {}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub struct RuleTransaction {
    merkle_proof: DataTree,
    rule_record_id: RecordID,
    touched_records: Vec<RecordID>,
    rule_arguments: Vec<u8>,
}

impl RuleTransaction {
    pub fn new<T: classic::Serialize>(
        proof: DataTree,
        rule: RecordID,
        touched_records: Vec<RecordID>,
        args: &T,
    ) -> Self {
        Self {
            merkle_proof: proof,
            rule_record_id: rule,
            touched_records: touched_records,
            rule_arguments: bincode::serialize(args).unwrap(),
        }
    }
}
