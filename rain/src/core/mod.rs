mod core;

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
