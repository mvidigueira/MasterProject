use macros::error;
use drop::net::{ConnectError, ReceiveError, SendError};
use merkle::MerkleError;
use drop::error::Error;

error! {
    type: ReplyError,
    description: "reply does not follow protocol"
}

error! {
    type: InconsistencyError,
    description: "merkle trees are not consistent"
}

error! {
    type: ClientError,
    causes: (ConnectError, SendError, ReceiveError, ReplyError, MerkleError, InconsistencyError),
    description: "client failure"
}