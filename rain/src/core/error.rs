use macros::error;
use std::io::Error as IoError;
use drop::net::{ReceiveError, SendError, ListenerError};
use drop::error::Error;

error! {
    type: CoreNodeError,
    causes: (IoError, ListenerError, SendError, ReceiveError),
    description: "server failure"
}