mod corenode;
mod tob_server;

pub use tob_server::TobServer;

use std::io::Error as IoError;

use drop::error::Error;
use drop::net::{ListenerError, SendError, ReceiveError};

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
}

type RecordID = String;

unsafe impl Send for TxRequest {}
unsafe impl Sync for TxRequest {}

impl classic::Message for TxRequest {}
