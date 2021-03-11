use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use serde::Serialize;

use drop::crypto::{key::exchange::Exchanger, Digest};
use drop::net::{Connector, DirectoryInfo, TcpConnector};

use crate::corenode::{
    BlsAggregateSignatures, BlsSigInfo, BlsSignature, CoreNodeInfo, DataTree,
    ExecuteResult, HistoryTree, PayloadForTob, RecordID, RuleTransaction,
    SystemConfig, TobRequest, Touch, UserCoreRequest,
    UserCoreResponse,
};

use super::{ClientError};

use futures::future::{self, FutureExt};
use std::future::Future;

use tracing::{error, info};

pub struct ClientNode {
    corenodes_config: SystemConfig<Arc<CoreNodeInfo>>,
    connector: TcpConnector,
    tob_info: DirectoryInfo,
}

impl ClientNode {
    pub fn new(
        tob_info: &DirectoryInfo,
        corenodes_config: &SystemConfig<Arc<CoreNodeInfo>>,
    ) -> Result<Self, ClientError> {
        let connector = TcpConnector::new(Exchanger::random());

        let ret = Self {
            corenodes_config: corenodes_config.clone(),
            connector: connector,
            tob_info: tob_info.clone(),
        };

        Ok(ret)
    }

    // Sends a request to get proof to all corenodes covering one of the records
    // Currently blocks if any of the nodes fail to reply (TO FIX)
    pub async fn get_merkle_proofs(
        &self,
        records: Vec<RecordID>,
    ) -> Result<(usize, DataTree), ClientError> {
        self.get_merkle_proofs_since(
            records,
            None,
        ).await
    }

    pub async fn get_merkle_proofs_since(
        &self,
        records: Vec<RecordID>,
        since: Option<usize>,
    ) -> Result<(usize, DataTree), ClientError> {
        let mut m = self.corenodes_config.assignments(&records);

        let txr: UserCoreRequest = if let Some(i) = since {
            (i, records.clone()).into()
        } else {
            records.clone().into()
        };
        let t = &txr;

        let mut results =
            future::join_all(m.drain().map(|(k, v)| async move {
                // change joinall to tolerate non-reponding nodes
                (v, self.get_merkle_proof(k.dir_info(), t).await)
            }))
            .await;

        let mut max = 0;
        let mut max_ind = 0;

        for i in 0..results.len() {
            if results[i].1.is_err() {
                return Err(results.remove(i).1.unwrap_err().into());
            }

            let (count, _) = results[i].1.as_ref().unwrap();
            if *count > max {
                max = *count;
                max_ind = i;
            }
        }

        let mut base = results.remove(max_ind).1.unwrap().1;

        for r in results.drain(..) {
            let t = r.1.unwrap().1;
            if HistoryTree::trees_are_consistent_given_records(
                &base, &t, &records,
            ) {
                HistoryTree::merge_consistent_trees(&mut base, &t, &records, 0);
            } else {
                error!("Inconsistency detected between proofs when collecting");
                return Err(ClientError::InconsistencyError{});
            }
        }

        Ok((max, base))
    }

    async fn get_merkle_proof(
        &self,
        corenode_info: &DirectoryInfo,
        records: &UserCoreRequest,
    ) -> Result<(usize, DataTree), ClientError> {
        match records {
            UserCoreRequest::Execute(_) => panic!(
                "'records' must be of the form &UserCoreRequest::GetProof"
            ),
            _ => (),
        }

        let mut connection = self
            .connector
            .connect(corenode_info.public(), &corenode_info.addr())
            .await?;

        connection.send(records).await?;
        info!("Awaiting response");
        let resp = connection.receive::<UserCoreResponse>().await?;
        info!("Received response!");
        match resp {
            UserCoreResponse::GetProof(proof) => Ok(proof),
            _ => return Err(ClientError::ReplyError{}),
        }
    }

    async fn send_execution_request(
        &self,
        corenode_info: &CoreNodeInfo,
        execute: &UserCoreRequest,
    ) -> Result<(ExecuteResult, BlsSignature), ClientError> {
        match execute {
            UserCoreRequest::GetProof(_) => panic!(
                "'records' must be of the form &UserCoreRequest::Execute"
            ),
            _ => (),
        }

        let mut connection = self
            .connector
            .connect(
                corenode_info.dir_info().public(),
                &corenode_info.dir_info().addr(),
            )
            .await?;

        connection.send(execute).await?;
        let resp = connection.receive::<UserCoreResponse>().await?;
        match resp {
            UserCoreResponse::Execute((result, sig)) => {
                let s: BlsSignature = sig.into();

                // Optional: verify signature here using CoreNodeInfo

                Ok((result, s))
            }
            _ => Err(ClientError::ReplyError{}),
        }
    }

    fn create_mask(nums: Vec<usize>, len: usize) -> Vec<bool> {
        let mut mask = vec![false; len];
        for i in nums {
            mask[i] = true;
        }
        mask
    }

    // Collects results from corenodes until there is a majority of replies with the same result
    async fn collect_results(
        futures: Vec<
            impl Future<
                    Output = (
                        usize,
                        Result<(ExecuteResult, BlsSignature), ClientError>,
                    ),
                > + Unpin,
        >,
    ) -> (ExecuteResult, BlsSigInfo) {
        let n = futures.len();
        let threshold = n / 2 + 1;

        let mut remaining = futures;

        let mut counts: HashMap<ExecuteResult, Vec<(usize, BlsSignature)>> =
            HashMap::new();

        loop {
            let ret = future::select_all(remaining).await;
            let (i, r) = ret.0;
            remaining = ret.2;

            if let Ok(r) = r {
                match counts.entry(r.0) {
                    Entry::Vacant(entry) => {
                        if threshold == 1 {
                            let sig =
                                BlsAggregateSignatures::from_sigs(vec![&r.1]);
                            let mask = Self::create_mask(vec![i], n);
                            return (
                                entry.into_key(),
                                BlsSigInfo::new(sig, mask),
                            );
                        } else {
                            entry.insert(vec![(i, r.1)]);
                        }
                    }
                    Entry::Occupied(mut entry) => {
                        if entry.get().len() + 1 == threshold {
                            let mut e = entry.remove_entry();
                            e.1.push((i, r.1));

                            let (nums, sigs): (Vec<usize>, Vec<BlsSignature>) =
                                e.1.drain(..).unzip();
                            let sig = BlsAggregateSignatures::from_sigs(
                                sigs.iter().collect(),
                            );
                            let mask = Self::create_mask(nums, n);

                            return (e.0, BlsSigInfo::new(sig, mask));
                        } else {
                            entry.get_mut().push((i, r.1));
                        }
                    }
                }
            }
        }
    }

    // Sends a request to execute to all corenodes responsible for running this rule
    // Currently blocks if any of the nodes fail to reply (TO FIX)
    pub async fn send_execution_requests<T: Serialize>(
        &self,
        proof: DataTree,
        rule: RecordID,
        rule_version: Digest,
        touched_records: Vec<RecordID>,
        args: &T,
    ) -> (ExecuteResult, BlsSigInfo) {
        let rt = RuleTransaction::new(
            proof,
            rule.clone(),
            rule_version,
            touched_records,
            args,
        );
        let mut m = self.corenodes_config.get_group_covering(&rule);
        m.sort_by(|x, y| x.dir_info().public().cmp(&y.dir_info().public()));

        let txr: &UserCoreRequest = &UserCoreRequest::Execute(rt);

        let f: Vec<_> = m
            .drain(..)
            .enumerate()
            .map(|(i, k)| {
                async move { (i, self.send_execution_request(k, txr).await) }
                    .boxed()
            })
            .collect();

        ClientNode::collect_results(f).await
    }

    // Missing signatures
    pub async fn send_apply_request(
        &self,
        rule_record_id: String,
        misc_digest: Digest,
        input: DataTree,
        result: Vec<(RecordID, Touch)>,
        bls_signature: BlsSigInfo,
    ) -> Result<(), ClientError> {
        let payload =
            PayloadForTob::new(rule_record_id, misc_digest, input, result);
        let txr = TobRequest::Apply((payload, bls_signature));

        let exchanger = Exchanger::random();
        let connector = TcpConnector::new(exchanger);
        let mut connection = connector
            .connect(self.tob_info.public(), &self.tob_info.addr())
            .await?;

        connection.send(&txr).await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use super::DataTree;
    use crate::utils::test::*;

    use std::time::Duration;
    use tokio::time::timeout;

    use tracing::{debug, info, trace_span};
    use tracing_futures::Instrument;

    #[tokio::test]
    async fn client_get_merkle_proofs() {
        init_logger();
        let nr_peer = 3;

        let mut t = DataTree::new();
        t.insert("Alan".to_string(), vec![0u8]);
        t.insert("Bob".to_string(), vec![1u8]);
        t.insert("Charlie".to_string(), vec![2u8]);

        let config =
            RunningConfig::setup(get_balanced_prefixes(nr_peer), t.clone(), 10)
                .await;

        let tob_info = &config.tob_info;
        let corenodes_config = &config.corenodes_config;

        async move {
            let client_node = ClientNode::new(tob_info, corenodes_config)
                .expect("client node creation failed");

            debug!("client node created");

            let (_, proof) = client_node
                .get_merkle_proofs(vec![
                    "Alan".to_string(),
                    "Bob".to_string(),
                    "Charlie".to_string(),
                ])
                .await
                .expect("merkle proof error");

            assert!(t.get_validator().validate(&proof));
        }
        .instrument(trace_span!("test_client_get_merkle_proofs"))
        .await;

        config.tear_down().await;
    }

    fn get_i32_from_result(k: &RecordID, proof: &DataTree) -> i32 {
        let mut value_array = [0 as u8; 4];
        let v = &proof.get(k).unwrap()[..value_array.len()];
        value_array.copy_from_slice(v);
        i32::from_be_bytes(value_array)
    }

    #[tokio::test]
    async fn client_send_execution_request() {
        init_logger();
        let nr_peer = 1;

        let filename =
            "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let rule_record_id = "transfer_rule".to_string();
        let rule_buffer =
            std::fs::read(filename).expect("could not load file into buffer");
        let rule_digest = drop::crypto::hash(&rule_buffer).unwrap();

        let mut t = DataTree::new();
        t.insert("Alice".to_string(), (1000i32).to_be_bytes().to_vec());
        t.insert("Bob".to_string(), (1000i32).to_be_bytes().to_vec());
        t.insert(rule_record_id.clone(), rule_buffer);

        let config =
            RunningConfig::setup(get_balanced_prefixes(nr_peer), t.clone(), 10)
                .await;

        let corenodes_config = &config.corenodes_config;
        let tob_info = &config.tob_info;

        async move {
            let client_node = ClientNode::new(tob_info, corenodes_config)
                .expect("client node creation failed");

            debug!("client node created");

            let (epoch, proof) = client_node
                .get_merkle_proofs(vec!["Alice".to_string(), "Bob".to_string()])
                .await
                .expect("merkle proof error");

            let args = ("Alice".to_string(), "Bob".to_string(), 50i32);
            let (res, bls_sig) = client_node
                .send_execution_requests(
                    proof.clone(),
                    rule_record_id.clone(),
                    rule_digest,
                    vec!["Alice".to_string(), "Bob".to_string()],
                    &args,
                )
                .await;

            client_node
                .send_apply_request(
                    rule_record_id.clone(),
                    res.misc_digest,
                    proof,
                    res.output.unwrap(),
                    bls_sig,
                )
                .await
                .expect("client error when sending apply request");

            // info!("Awaiting");
            let _ = timeout(Duration::from_millis(1000), future::pending::<()>()).await;

            let (_, result) = client_node
                .get_merkle_proofs_since(
                    vec!["Alice".to_string(), "Bob".to_string()],
                    Some(epoch+1),
                )
                .await
                .expect("merkle proof error");

            assert_eq!(get_i32_from_result(&"Alice".to_string(), &result), 950);
            assert_eq!(get_i32_from_result(&"Bob".to_string(), &result), 1050);
        }
        .instrument(trace_span!("test_client_send_execution_request"))
        .await;

        config.tear_down().await;
    }

    #[tokio::test]
    async fn late_request_consistent() {
        init_logger();
        let nr_peer = 1;

        let filename =
            "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let rule_record_id = "transfer_rule".to_string();
        let rule_buffer =
            std::fs::read(filename).expect("could not load file into buffer");
        let rule_digest = drop::crypto::hash(&rule_buffer).unwrap();

        let mut t = DataTree::new();
        t.insert("Alice".to_string(), (1000i32).to_be_bytes().to_vec());
        t.insert("Bob".to_string(), (1000i32).to_be_bytes().to_vec());
        t.insert("Charlie".to_string(), (1000i32).to_be_bytes().to_vec());
        t.insert("Dave".to_string(), (1000i32).to_be_bytes().to_vec());
        t.insert(rule_record_id.clone(), rule_buffer);

        let config =
            RunningConfig::setup(get_balanced_prefixes(nr_peer), t.clone(), 10)
                .await;
        let corenodes_config = &config.corenodes_config;
        let tob_info = &config.tob_info;

        async move {
            let client_node_1 = ClientNode::new(tob_info, corenodes_config)
                .expect("client node 1 creation failed");

            let client_node_2 = ClientNode::new(tob_info, corenodes_config)
                .expect("client node 2 creation failed");

            let (epoch_1, proof_1) = client_node_1
                .get_merkle_proofs(vec!["Alice".to_string(), "Bob".to_string()])
                .await
                .expect("merkle proof error");

            let (epoch_2, proof_2) = client_node_2
                .get_merkle_proofs(vec![
                    "Charlie".to_string(),
                    "Dave".to_string(),
                ])
                .await
                .expect("merkle proof error");

            let args_1 = ("Alice".to_string(), "Bob".to_string(), 50i32);
            let (res, bls_sig) = client_node_1
                .send_execution_requests(
                    proof_1.clone(),
                    rule_record_id.clone(),
                    rule_digest,
                    vec!["Alice".to_string(), "Bob".to_string()],
                    &args_1,
                )
                .await;
            client_node_1
                .send_apply_request(
                    rule_record_id.clone(),
                    res.misc_digest,
                    proof_1,
                    res.output.unwrap(),
                    bls_sig,
                )
                .await
                .expect("client error when sending apply request");

            let args_2 = ("Charlie".to_string(), "Dave".to_string(), 50i32);
            let (res, bls_sig) = client_node_2
                .send_execution_requests(
                    proof_2.clone(),
                    rule_record_id.clone(),
                    rule_digest,
                    vec!["Charlie".to_string(), "Dave".to_string()],
                    &args_2,
                )
                .await;
            client_node_2
                .send_apply_request(
                    rule_record_id.clone(),
                    res.misc_digest,
                    proof_2,
                    res.output.unwrap(),
                    bls_sig,
                )
                .await
                .expect("client error when sending apply request");

            //tokio::time::sleep(std::time::Duration::from_millis(2000)).await;

            let (_, result) = client_node_1
                .get_merkle_proofs_since(
                    vec![
                        "Alice".to_string(),
                        "Bob".to_string(),
                        "Charlie".to_string(),
                        "Dave".to_string(),
                        ],
                    Some(epoch_1+2)
                )
                .await
                .expect("merkle proof error");

            assert_eq!(get_i32_from_result(&"Alice".to_string(), &result), 950);
            assert_eq!(get_i32_from_result(&"Bob".to_string(), &result), 1050);
            assert_eq!(
                get_i32_from_result(&"Charlie".to_string(), &result),
                950
            );
            assert_eq!(get_i32_from_result(&"Dave".to_string(), &result), 1050);
        }
        .instrument(trace_span!("test_late_request_consistent"))
        .await;

        config.tear_down().await;
    }

    #[tokio::test]
    async fn late_request_not_consistent() {
        init_logger();
        let nr_peer = 1;

        let filename =
            "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let rule_record_id = "transfer_rule".to_string();
        let rule_buffer =
            std::fs::read(filename).expect("could not load file into buffer");
        let rule_digest = drop::crypto::hash(&rule_buffer).unwrap();

        let mut t = DataTree::new();
        t.insert("Alice".to_string(), (1000i32).to_be_bytes().to_vec());
        t.insert("Bob".to_string(), (1000i32).to_be_bytes().to_vec());
        t.insert(rule_record_id.clone(), rule_buffer);

        let config =
            RunningConfig::setup(get_balanced_prefixes(nr_peer), t.clone(), 10)
                .await;
        let corenodes_config = &config.corenodes_config;
        let tob_info = &config.tob_info;

        async move {
            let client_node_1 = ClientNode::new(tob_info, corenodes_config)
                .expect("client node 1 creation failed");

            let client_node_2 = ClientNode::new(tob_info, corenodes_config)
                .expect("client node 2 creation failed");

            let (epoch, proof) = client_node_1
                .get_merkle_proofs(vec![
                    "Alice".to_string(),
                    "Bob".to_string(),
                ])
                .await
                .expect("merkle proof error");

            let args_1 = ("Alice".to_string(), "Bob".to_string(), 50i32);
            let (res, bls_sig) = client_node_1
                .send_execution_requests(
                    proof.clone(),
                    rule_record_id.clone(),
                    rule_digest,
                    vec![
                        "Alice".to_string(),
                        "Bob".to_string(),
                    ],
                    &args_1,
                )
                .await;
            client_node_1
                .send_apply_request(
                    rule_record_id.clone(),
                    res.misc_digest,
                    proof.clone(),
                    res.output.unwrap(),
                    bls_sig,
                )
                .await
                .expect("client error when sending apply request");

            let args_2 = ("Charlie".to_string(), "Dave".to_string(), 50i32);
            let (res, _) = client_node_2
                .send_execution_requests(
                    proof.clone(),
                    rule_record_id.clone(),
                    rule_digest,
                    vec![
                        "Charlie".to_string(),
                        "Dave".to_string(),
                    ],
                    &args_2,
                )
                .await;
            res.output.expect_err("Expected an error processing transaction due to the invalidated merkle proof");

            let (_, result) = client_node_1
                .get_merkle_proofs_since(
                    vec!["Alice".to_string(), "Bob".to_string()],
                    Some(epoch+1),
                )
                .await
                .expect("merkle proof error");

            assert_eq!(get_i32_from_result(&"Alice".to_string(), &result), 950);
            assert_eq!(get_i32_from_result(&"Bob".to_string(), &result), 1050);
        }
        .instrument(trace_span!("test_late_request_not_consistent"))
        .await;

        config.tear_down().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn request_in_ancient_history() {
        init_logger();
        let nr_peer = 3;

        let filename =
            "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let rule_record_id = "transfer_rule".to_string();
        let rule_buffer =
            std::fs::read(filename).expect("could not load file into buffer");
        let rule_digest = drop::crypto::hash(&rule_buffer).unwrap();

        let mut t = DataTree::new();
        let records = [
            "Alice", "Bob", "Charlie", "Dave", "Aaron", "Vanessa", "Justin",
            "Irina",
        ];
        for &k in records.iter() {
            t.insert(String::from(k), (1000i32).to_be_bytes().to_vec());
        }
        t.insert(rule_record_id.clone(), rule_buffer);

        let config =
            RunningConfig::setup(get_balanced_prefixes(nr_peer), t.clone(), 2)
                .await;
        let corenodes_config = &config.corenodes_config;
        let tob_info = &config.tob_info;

        async move {
            let client_node_1 = ClientNode::new(tob_info, corenodes_config)
                .expect("client node 1 creation failed");

            let (epoch_1, proof_1) = client_node_1
                .get_merkle_proofs(vec!["Alice".to_string(), "Bob".to_string()])
                .await
                .expect("merkle proof error");

            let args_1 = ("Alice".to_string(), "Bob".to_string(), 50i32);
            let (res, bls_sig) = client_node_1
                .send_execution_requests(
                    proof_1.clone(),
                    rule_record_id.clone(),
                    rule_digest,
                    vec!["Alice".to_string(), "Bob".to_string()],
                    &args_1,
                )
                .await;
            client_node_1
                .send_apply_request(
                    rule_record_id.clone(),
                    res.misc_digest,
                    proof_1,
                    res.output.unwrap(),
                    bls_sig,
                )
                .await
                .expect("client error when sending apply request");

            let (epoch_2, proof_1) = client_node_1
                .get_merkle_proofs(vec![
                    "Charlie".to_string(),
                    "Dave".to_string(),
                ])
                .await
                .expect("merkle proof error");

            let args_1 = ("Charlie".to_string(), "Dave".to_string(), 100i32);
            let (res, bls_sig) = client_node_1
                .send_execution_requests(
                    proof_1.clone(),
                    rule_record_id.clone(),
                    rule_digest,
                    vec!["Charlie".to_string(), "Dave".to_string()],
                    &args_1,
                )
                .await;
            client_node_1
                .send_apply_request(
                    rule_record_id.clone(),
                    res.misc_digest,
                    proof_1,
                    res.output.unwrap(),
                    bls_sig,
                )
                .await
                .expect("client error when sending apply request");

            let _ =
                timeout(Duration::from_secs(2), future::pending::<()>()).await;

            let (_, result) = client_node_1
                .get_merkle_proofs_since(
                    [
                        "Alice", "Bob", "Charlie", "Dave", "Aaron", "Vanessa",
                        "Justin", "Irina",
                    ]
                    .iter()
                    .map(|x| String::from(*x))
                    .collect(),
                    Some(epoch_2+1),
                )
                .await
                .expect("merkle proof error");

            assert_eq!(get_i32_from_result(&"Alice".to_string(), &result), 950);
            assert_eq!(get_i32_from_result(&"Bob".to_string(), &result), 1050);
            assert_eq!(
                get_i32_from_result(&"Charlie".to_string(), &result),
                900
            );
            assert_eq!(get_i32_from_result(&"Dave".to_string(), &result), 1100);
            assert_eq!(
                get_i32_from_result(&"Aaron".to_string(), &result),
                1000
            );
            assert_eq!(
                get_i32_from_result(&"Vanessa".to_string(), &result),
                1000
            );
            assert_eq!(
                get_i32_from_result(&"Justin".to_string(), &result),
                1000
            );
            assert_eq!(
                get_i32_from_result(&"Irina".to_string(), &result),
                1000
            );
        }
        .instrument(trace_span!("test_request_in_ancient_history"))
        .await;

        config.tear_down().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mixed_get_proofs() {
        init_logger();
        let nr_peer = 3;

        let filename =
            "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let rule_record_id = "transfer_rule".to_string();
        let rule_buffer =
            std::fs::read(filename).expect("could not load file into buffer");
        let rule_digest = drop::crypto::hash(&rule_buffer).unwrap();

        let mut t = DataTree::new();
        let records = [
            "Alice", "Bob", "Charlie", "Dave", "Aaron", "Vanessa", "Justin",
            "Irina",
        ];
        for &k in records.iter() {
            t.insert(String::from(k), (1000i32).to_be_bytes().to_vec());
        }

        t.insert(rule_record_id.clone(), rule_buffer);

        // Setup a tob which only broadcasts to one of the nodes
        let config = RunningConfig::setup_asymetric(
            get_balanced_prefixes(nr_peer),
            1,
            t.clone(),
            10,
        )
        .await;
        let corenodes_config = &config.corenodes_config;
        let tob_info = &config.tob_info;

        async move {
            let client_node_1 = ClientNode::new(tob_info, corenodes_config)
                .expect("client node 1 creation failed");

            let (_, proof_1) = client_node_1
                .get_merkle_proofs(vec!["Alice".to_string(), "Bob".to_string()])
                .await
                .expect("merkle proof error");

            let args_1 = ("Alice".to_string(), "Bob".to_string(), 50i32);
            client_node_1
                .send_execution_requests(
                    proof_1,
                    rule_record_id.clone(),
                    rule_digest,
                    vec!["Alice".to_string(), "Bob".to_string()],
                    &args_1,
                )
                .await;

            let _ =
                timeout(Duration::from_secs(5), future::pending::<()>()).await;

            let (_, proof_1) = client_node_1
                .get_merkle_proofs(vec![
                    "Charlie".to_string(),
                    "Dave".to_string(),
                ])
                .await
                .expect("merkle proof error");

            let args_1 = ("Charlie".to_string(), "Dave".to_string(), 100i32);
            client_node_1
                .send_execution_requests(
                    proof_1,
                    rule_record_id.clone(),
                    rule_digest,
                    vec!["Charlie".to_string(), "Dave".to_string()],
                    &args_1,
                )
                .await;

            let _ =
                timeout(Duration::from_secs(5), future::pending::<()>()).await;

            let (_, proof_1) = client_node_1
                .get_merkle_proofs(vec![
                    "Aaron".to_string(),
                    "Vanessa".to_string(),
                ])
                .await
                .expect("merkle proof error");

            let args_1 = ("Aaron".to_string(), "Vanessa".to_string(), 150i32);
            client_node_1
                .send_execution_requests(
                    proof_1,
                    rule_record_id.clone(),
                    rule_digest,
                    vec!["Aaron".to_string(), "Vanessa".to_string()],
                    &args_1,
                )
                .await;

            let _ =
                timeout(Duration::from_secs(5), future::pending::<()>()).await;

            let (_, proof_1) = client_node_1
                .get_merkle_proofs(vec![
                    "Justin".to_string(),
                    "Irina".to_string(),
                ])
                .await
                .expect("merkle proof error");

            let args_1 = ("Justin".to_string(), "Irina".to_string(), 200i32);
            client_node_1
                .send_execution_requests(
                    proof_1,
                    rule_record_id.clone(),
                    rule_digest,
                    vec!["Justin".to_string(), "Irina".to_string()],
                    &args_1,
                )
                .await;
        }
        .instrument(trace_span!("test_mixed_get_proofs"))
        .await;

        config.tear_down().await;
    }

    use std::time::Instant;

    #[tokio::test]
    async fn merkle_proof_time() {
        init_logger();
        let nr_peer = 3;

        let filename =
            "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let rule_record_id = "transfer_rule".to_string();
        let rule_buffer =
            std::fs::read(filename).expect("could not load file into buffer");

        let mut t = DataTree::new();
        let records = [
            "Alice", "Bob", "Charlie", "Dave", "Aaron", "Vanessa", "Justin",
            "Irina",
        ];
        for &k in records.iter() {
            t.insert(String::from(k), (1000i32).to_be_bytes().to_vec());
        }
        t.insert(rule_record_id.clone(), rule_buffer);

        let config =
            RunningConfig::setup(get_balanced_prefixes(nr_peer), t.clone(), 2)
                .await;
        let corenodes_config = &config.corenodes_config;
        let tob_info = &config.tob_info;

        async move {
            let client_node_1 = ClientNode::new(tob_info, corenodes_config)
                .expect("client node 1 creation failed");

            let mut v: Vec<Instant> = vec![Instant::now()];

            for _ in 1i32..100i32 {
                let _ = client_node_1
                    .get_merkle_proofs(vec![
                        "Alice".to_string(),
                        "Bob".to_string(),
                        // rule_record_id.clone(),
                    ])
                    .await
                    .expect("merkle proof error");

                v.push(Instant::now());
            }

            let mut vd: Vec<Duration> = vec![];
            for i in 0..v.len() - 1 {
                vd.push(v[i + 1] - v[i])
            }

            vd.sort();
            info!("Median: {:?}\nDurations: {:?}", vd.get(50).unwrap(), vd)
        }
        .instrument(trace_span!("test_merkle_proof_time"))
        .await;

        config.tear_down().await;
    }

    // #[tokio::test]
    async fn _memory_footprint() {
        init_logger();
        let nr_peer = 5;

        let filename =
            "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let rule_record_id = "transfer_rule".to_string();
        let rule_buffer =
            std::fs::read(filename).expect("could not load file into buffer");
        let rule_digest = drop::crypto::hash(&rule_buffer).unwrap();

        let mut t = DataTree::new();
        for i in 0..1000 {
            t.insert(i.to_string(), vec![0]);
        }
        t.insert(rule_record_id.clone(), rule_buffer);

        let config =
            RunningConfig::setup(get_balanced_prefixes(nr_peer), t.clone(), 3)
                .await;
        let corenodes_config = &config.corenodes_config;
        let tob_info = &config.tob_info;

        async move {
            let client_node = ClientNode::new(tob_info, corenodes_config)
                .expect("client node creation failed");

            debug!("client node created");

            for _ in 0..4 {
                let (epoch, proof) = client_node
                    .get_merkle_proofs(vec![
                        1.to_string(),
                        rule_record_id.clone(),
                    ])
                    .await
                    .expect("merkle proof error");

                // info!("Awaiting");
                // let _ = timeout(Duration::from_millis(2000), future::pending::<()>()).await;

                let v: Vec<u8> = vec![0];
                let args = (1.to_string(), v);
                client_node
                    .send_execution_requests(
                        proof,
                        rule_record_id.clone(),
                        rule_digest,
                        vec![1.to_string(), rule_record_id.clone()],
                        &args,
                    )
                    .await;
            }

            let _ =
                timeout(Duration::from_millis(2000), future::pending::<()>())
                    .await;

            for _ in 0..1 {
                let (epoch, proof) = client_node
                    .get_merkle_proofs(vec![
                        2.to_string(),
                        rule_record_id.clone(),
                    ])
                    .await
                    .expect("merkle proof error");

                // info!("Awaiting");
                // let _ = timeout(Duration::from_millis(2000), future::pending::<()>()).await;

                let v: Vec<u8> = vec![1u8; 10000];
                let args = (2.to_string(), v);
                client_node
                    .send_execution_requests(
                        proof,
                        rule_record_id.clone(),
                        rule_digest,
                        vec![2.to_string(), rule_record_id.clone()],
                        &args,
                    )
                    .await;
            }

            for _ in 0..4 {
                let (epoch, proof) = client_node
                    .get_merkle_proofs(vec![
                        1.to_string(),
                        rule_record_id.clone(),
                    ])
                    .await
                    .expect("merkle proof error");

                let v: Vec<u8> = vec![0];
                let args = (1.to_string(), v);
                client_node
                    .send_execution_requests(
                        proof,
                        rule_record_id.clone(),
                        rule_digest,
                        vec![1.to_string(), rule_record_id.clone()],
                        &args,
                    )
                    .await;
            }
        }
        .instrument(trace_span!("test_memory_footpring"))
        .await;

        config.tear_down().await;
    }

    use rand::prelude::*;

    // #[tokio::test]
    async fn _success_rate() {
        init_logger();
        let nr_peer = 1;

        let filename =
            "contract_3/target/wasm32-unknown-unknown/release/contract_test.wasm";
        let rule_record_id = "transfer_rule".to_string();
        let rule_buffer =
            std::fs::read(filename).expect("could not load file into buffer");
        let rule_digest = drop::crypto::hash(&rule_buffer).unwrap();

        let mut t = DataTree::new();
        for i in 0..1000 {
            t.insert(i.to_string(), vec![0]);
        }
        t.insert(rule_record_id.clone(), rule_buffer);

        let config =
            RunningConfig::setup(get_balanced_prefixes(nr_peer), t.clone(), 20)
                .await;
        let corenodes_config = &config.corenodes_config;
        let tob_info = &config.tob_info;

        async move {
            let client_node = ClientNode::new(tob_info, corenodes_config)
                .expect("client node creation failed");

            debug!("client node created");

            let mut rng = rand::thread_rng();
            let mut nums: Vec<i32> = (0..1000).collect();
            let mut execs = vec![];
            for _ in 0..100i32 {
                nums.shuffle(&mut rng);
                let n = nums[0];
                let (epoch, proof) = client_node
                    .get_merkle_proofs(vec![
                        n.to_string(),
                        rule_record_id.clone(),
                    ])
                    .await
                    .expect("merkle proof error");
                execs.push((proof, n));
            }

            for (p, n) in execs {
                let v: Vec<u8> = vec![1];
                let args = (n.to_string(), v);
                client_node
                    .send_execution_requests(
                        p,
                        rule_record_id.clone(),
                        rule_digest,
                        vec![n.to_string(), rule_record_id.clone()],
                        &args,
                    )
                    .await;
            }

            let _ =
                timeout(Duration::from_millis(2000), future::pending::<()>())
                    .await;

            let v: Vec<String> = (0..1000i32).map(|n| n.to_string()).collect();
            let (epoch, proof_final) = client_node
                .get_merkle_proofs(v.clone())
                .await
                .expect("merkle proof error");

            let mut total = 0;
            for i in v {
                match proof_final.get(&i) {
                    Ok(v1) => {
                        if *v1 == vec![1u8] {
                            total += 1;
                        } else if *v1 == vec![0u8] {
                            total += 0;
                        } else {
                            panic!("Problem 1");
                        }
                    }
                    Err(_) => {
                        panic!("Problem 2");
                    }
                }
            }

            info!("Total is: {}", total);
        }
        .instrument(trace_span!("test_success_rate"))
        .await;

        config.tear_down().await;
    }
}
