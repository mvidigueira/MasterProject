mod corenode;
mod tob_server;

pub use tob_server::TobServer;

use std::io::Error as IoError;

use drop::error::Error;
use drop::net::{ListenerError, SendError};

use macros::error;

error! {
    type: CoreNodeError,
    causes: (IoError, ListenerError, SendError),
    description: "server failure"
}

error! {
    type: TobServerError,
    causes: (IoError, ListenerError, SendError),
    description: "server failure"
}

#[derive(
    classic::Serialize,
    classic::Deserialize,
    Debug,
    Copy,
    Clone,
    Hash,
    PartialEq,
    Eq,
)]
struct TxRequest;

unsafe impl Send for TxRequest {}
unsafe impl Sync for TxRequest {}

impl classic::Message for TxRequest {}
