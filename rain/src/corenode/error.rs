use drop::error::Error;
use drop::net::{ListenerError, ReceiveError, SendError};
use macros::error;
use std::io::Error as IoError;

error! {
    type: CoreNodeError,
    causes: (IoError, ListenerError, SendError, ReceiveError),
    description: "server failure"
}
