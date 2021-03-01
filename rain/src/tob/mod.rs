mod tob;
mod error;

use error::{TobServerError, BroadcastError};

pub use super::corenode::Info as CoreNodeInfo;
pub use tob_server::TobServer;

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub enum Touch {
    Read,
    Deleted,
    Modified(RecordVal),
    Added(RecordVal),
}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub enum TobRequest {
    Apply((PayloadForTob, BlsSigInfo)),
}

unsafe impl Send for TobRequest {}
unsafe impl Sync for TobRequest {}
impl classic::Message for TobRequest {}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub struct PayloadForTob {
    rule_record_id: String,
    input_merkle_proof: DataTree,
    misc_digest: Digest, // hash(rule_version, args)
    output: Vec<(RecordID, Touch)>,
}

impl PayloadForTob {
    pub fn new(
        rule_record_id: String,
        misc_digest: Digest,
        input_merkle_proof: DataTree,
        output: Vec<(RecordID, Touch)>,
    ) -> Self {
        Self {
            rule_record_id,
            misc_digest,
            input_merkle_proof,
            output,
        }
    }
}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub enum TobResponse {
    Result(String),
}

unsafe impl Send for TobResponse {}
unsafe impl Sync for TobResponse {}
impl classic::Message for TobResponse {}
