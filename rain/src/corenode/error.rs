use drop::net::{ListenerError, ReceiveError, SendError};
use std::io::Error as IoError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreNodeError {
    #[error("CoreNodeError Error: {source}")]
    IoError {
        #[from]
        source: IoError,
    },

    #[error("Corenode Error:  {source}")]
    ListenerError {
        #[from]
        source: ListenerError,
    },

    #[error("Corenode Error:  {source}")]
    SendError {
        #[from]
        source: SendError,
    },

    #[error("Corenode Error:  {source}")]
    ReceiveError {
        #[from]
        source: ReceiveError,
    },
}