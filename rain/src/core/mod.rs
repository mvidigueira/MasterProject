mod client;
mod corenode;
mod tob_server;

#[cfg(test)]
pub mod test;

pub use tob_server::TobServer;
pub use corenode::CoreNode;
pub use client::ClientNode;

use std::io::Error as IoError;

use drop::crypto::{self, Digest};
use drop::error::Error;
use drop::net::{DirectoryInfo, ListenerError, ReceiveError, SendError, ConnectError};

use merkle::{Tree, error::MerkleError};

use macros::error;

error! {
    type: ReplyError,
    description: "reply does not follow protocol"
}

error! {
    type: ClientError,
    causes: (ConnectError, SendError, ReceiveError, ReplyError, MerkleError),
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
    Execute(),
}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
enum TxResponse {
    GetProof(Tree<RecordID, RecordVal>),
    Execute(String),
}

unsafe impl Send for TxRequest {}
unsafe impl Sync for TxRequest {}
impl classic::Message for TxRequest {}

unsafe impl Send for TxResponse {}
unsafe impl Sync for TxResponse {}
impl classic::Message for TxResponse {}

fn closest<'a>(
    sorted_corenodes: &'a Vec<(Digest, DirectoryInfo)>,
    key: &RecordID,
) -> &'a DirectoryInfo {
    let key_d = crypto::hash(key).unwrap();
    let r = sorted_corenodes
        .binary_search_by_key(key_d.as_ref(), |x| *x.0.as_ref());
    match r {
        Ok(i) => &sorted_corenodes[i].1,
        Err(i) => {
            if sorted_corenodes.len() <= i {
                &sorted_corenodes.last().unwrap().1
            } else if i == 0 {
                &sorted_corenodes.last().unwrap().1
            } else {
                &sorted_corenodes[i].1
            }
        }
    }
}
