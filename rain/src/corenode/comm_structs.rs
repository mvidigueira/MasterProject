use super::{BlsSignature, DataTree, Digest, RecordID, RecordVal};
use merkle::Tree;

use std::hash::{Hash, Hasher};

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub enum UserCoreRequest {
    // Request from User to Corenode
    GetProof(Vec<RecordID>),
    Execute(RuleTransaction),
}

impl From<Vec<RecordID>> for UserCoreRequest {
    fn from(v: Vec<RecordID>) -> Self {
        UserCoreRequest::GetProof(v)
    }
}
unsafe impl Send for UserCoreRequest {}
unsafe impl Sync for UserCoreRequest {}
impl classic::Message for UserCoreRequest {}

#[derive(classic::Serialize, classic::Deserialize, Debug, Clone, PartialEq)]
pub struct BlsSigWrapper(BlsSignature);
impl Eq for BlsSigWrapper {}
impl Hash for BlsSigWrapper {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}
impl From<BlsSignature> for BlsSigWrapper {
    fn from(sig: BlsSignature) -> Self {
        BlsSigWrapper(sig)
    }
}
impl From<BlsSigWrapper> for BlsSignature {
    fn from(wrapper: BlsSigWrapper) -> Self {
        wrapper.0
    }
}

#[derive(classic::Serialize, classic::Deserialize, Debug, Clone, PartialEq)]
pub struct BlsSigInfo {
    sig: BlsSignature,
    mask: Vec<bool>,
}
impl Eq for BlsSigInfo {}
impl Hash for BlsSigInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sig.to_bytes().hash(state);
        self.mask.hash(state);
    }
}
impl BlsSigInfo {
    pub fn new(sig: BlsSignature, mask: Vec<bool>) -> Self {
        Self { sig, mask }
    }

    pub fn sig(&self) -> &BlsSignature {
        &self.sig
    }
    pub fn mask(&self) -> &Vec<bool> {
        &self.mask
    }
}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub enum UserCoreResponse {
    GetProof((usize, Tree<RecordID, RecordVal>)),
    Execute((ExecuteResult, BlsSigWrapper)),
}

unsafe impl Send for UserCoreResponse {}
unsafe impl Sync for UserCoreResponse {}
impl classic::Message for UserCoreResponse {}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub struct ExecuteResult {
    pub rule_record_id: String,
    pub rule_version: Digest,
    pub misc_digest: Digest, // hash(rule_version, args)
    pub output: Result<Vec<(RecordID, Touch)>, String>,
}

pub fn get_misc_digest(rule_version: &Digest, args: &Vec<u8>) -> Digest {
    drop::crypto::hash(&(rule_version, args)).unwrap()
}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub enum Touch {
    Read,
    Deleted,
    Modified(RecordVal),
    Added(RecordVal),
}

impl ExecuteResult {
    pub fn new(
        rule_record_id: RecordID,
        rule_version: Digest,
        misc_digest: Digest,
        ledger: Vec<(RecordID, Touch)>,
    ) -> Self {
        Self {
            rule_record_id,
            rule_version,
            misc_digest,
            output: Ok(ledger),
        }
    }

    pub fn fail(
        rule_record_id: RecordID,
        rule_version: Digest,
        misc_digest: Digest,
        cause: String,
    ) -> Self {
        Self {
            rule_record_id,
            rule_version,
            misc_digest: misc_digest,
            output: Err(cause),
        }
    }
}

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub struct RuleTransaction {
    merkle_proof: DataTree,
    rule_record_id: RecordID,
    rule_version: Digest,
    touched_records: Vec<RecordID>,
    rule_arguments: Vec<u8>,
}

impl RuleTransaction {
    pub fn new<T: classic::Serialize>(
        proof: DataTree,
        rule: RecordID,
        rule_digest: Digest,
        touched_records: Vec<RecordID>,
        args: &T,
    ) -> Self {
        Self {
            merkle_proof: proof,
            rule_record_id: rule,
            rule_version: rule_digest,
            touched_records: touched_records,
            rule_arguments: bincode::serialize(args).unwrap(),
        }
    }

    pub fn proof(&self) -> &DataTree {
        &self.merkle_proof
    }
    pub fn rule_id(&self) -> &RecordID {
        &self.rule_record_id
    }
    pub fn rule_version(&self) -> &Digest {
        &self.rule_version
    }
    pub fn touched_records(&self) -> &Vec<RecordID> {
        &self.touched_records
    }
    pub fn rule_arguments(&self) -> &Vec<u8> {
        &self.rule_arguments
    }
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

    pub fn proof(&self) -> &DataTree {
        &self.input_merkle_proof
    }
    pub fn rule_id(&self) -> &RecordID {
        &self.rule_record_id
    }
    pub fn misc_digest(&self) -> &Digest {
        &self.misc_digest
    }
    pub fn output(&self) -> &Vec<(RecordID, Touch)> {
        &self.output
    }
}

// pub fn corenode_bls_sign(payload: &PayloadForTob) -> {
//     let d = drop::crypto::hash(payload).unwrap();

// }

#[derive(
    classic::Serialize, classic::Deserialize, Debug, Clone, Hash, PartialEq, Eq,
)]
pub enum TobResponse {
    Result(String),
}

unsafe impl Send for TobResponse {}
unsafe impl Sync for TobResponse {}
impl classic::Message for TobResponse {}
