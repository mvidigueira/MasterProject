use drop::net::{ListenerError, SendError};
use std::io::Error as IoError;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TobServerError {
    #[error("Tob Server Error: {source}")]
    IoError {
        #[from]
        source: IoError,
    },

    #[error("Tob Server Error::  {source}")]
    ListenerError {
        #[from]
        source: ListenerError,
    },

    #[error("Corenode Error:  {source}")]
    SendError {
        #[from]
        source: SendError,
    },
}