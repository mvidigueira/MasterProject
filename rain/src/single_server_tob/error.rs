use drop::error::Error;
use drop::net::{ListenerError, SendError};
use macros::error;
use std::io::Error as IoError;

error! {
    type: BroadcastError,
    description: "broadcast failure"
}

error! {
    type: TobServerError,
    causes: (IoError, ListenerError, SendError, BroadcastError),
    description: "server failure"
}
