mod corenode;
mod tob_server;

pub use tob_server::TobServer;

use std::io::Error as IoError;

use drop::error::Error;
use drop::net::{ListenerError, SendError, ReceiveError};

use merkle::Tree;

use macros::error;

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

#[derive(
    classic::Serialize,
    classic::Deserialize,
    Debug,
    Clone,
    Hash,
    PartialEq,
    Eq,
)]
enum TxRequest {
    GetProof(Vec<RecordID>),
    Execute(),
}

#[derive(
    classic::Serialize,
    classic::Deserialize,
    Debug,
    Clone,
    Hash,
    PartialEq,
    Eq,
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