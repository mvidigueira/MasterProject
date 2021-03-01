use macros::error;
use std::io::Error as IoError;
use drop::net::{ListenerError, SendError};
use drop::error::Error;

error! {
    type: BroadcastError,
    description: "broadcast failure"
}

error! {
    type: TobServerError,
    causes: (IoError, ListenerError, SendError, BroadcastError),
    description: "server failure"
}