use drop::net::{ConnectError, ReceiveError, SendError};
use merkle::MerkleError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("reply does not follow protocol")]
    ReplyError,

    #[error("merkle trees are not consistent")]
    InconsistencyError,

    #[error("Client Error: {source}")]
    ConnectError {
        #[from]
        source: ConnectError,
    },

    #[error("Client Error: {source}")]
    SendError {
        #[from]
        source: SendError,
    },

    #[error("Client Error: {source}")]
    ReceiveError {
        #[from]
        source: ReceiveError,
    },

    #[error("Client Error: {source}")]
    MerkleError {
        #[from]
        source: MerkleError,
    },
}