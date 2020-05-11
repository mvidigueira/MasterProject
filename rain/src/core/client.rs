use std::collections::HashMap;

use drop::crypto::key::exchange::Exchanger;
use drop::crypto::{self, Digest};
use drop::net::{Connector, DirectoryConnector, DirectoryInfo, TcpConnector};

use super::{
    closest, DataTree, RecordID, RuleTransaction, TxRequest, TxResponse, history_tree::HistoryTree
};

use super::{ClientError, ReplyError};

use futures::future;

use tracing::{error, debug};

pub struct ClientNode {
    corenodes: Vec<(Digest, DirectoryInfo)>,
    connector: TcpConnector,
    tob_info: DirectoryInfo,
}

impl ClientNode {
    pub async fn new(
        tob_info: &DirectoryInfo,
        dir_info: &DirectoryInfo,
        nr_peer: usize,
    ) -> Result<Self, ClientError> {
        let exchanger = Exchanger::random();

        let connector = TcpConnector::new(exchanger.clone());

        let mut dir_connector = DirectoryConnector::new(connector);

        debug!("Waiting for corenodes to join directory");

        let mut corenodes = if nr_peer > 0 {
            dir_connector
                .wait(nr_peer, dir_info)
                .await
                .expect("could not wait")
        } else {
            Vec::new()
        };

        drop(dir_connector);

        let mut corenodes: Vec<(Digest, DirectoryInfo)> = corenodes
            .drain(..)
            .map(|info| (crypto::hash(info.public()).unwrap(), info))
            .collect();

        corenodes.sort_by_key(|x| *x.0.as_ref());

        let connector = TcpConnector::new(exchanger);

        let ret = Self {
            corenodes: corenodes,
            connector: connector,
            tob_info: tob_info.clone(),
        };

        Ok(ret)
    }

    pub async fn get_merkle_proofs(
        &self,
        records: Vec<RecordID>,
    ) -> Result<DataTree, ClientError> {
        let mut m: HashMap<DirectoryInfo, Vec<RecordID>> = HashMap::new();

        for r_id in records {
            let info = closest(&self.corenodes, &r_id);
            if !m.contains_key(info) {
                m.insert(info.clone(), Vec::new());
            }
            m.get_mut(info).unwrap().push(r_id);
        }

        let mut results =
            future::join_all(m.drain().map(|(k, v)| async move {
                (v.clone(), self.get_merkle_proof(&k, v).await)
            }))
            .await;

        let mut h_tree = HistoryTree::new(1, drop::crypto::hash(&0).unwrap(), vec!());
        let mut max = 0;
        let mut max_ind = 0;

        for i in 0..results.len() {
            if results[i].1.is_err() {
                return Err(results.remove(i).1.unwrap_err().into())
            }

            let (count, _) = results[i].1.as_ref().unwrap();
            if *count > max {
                max = *count;
                max_ind = i;
            }
        }

        h_tree.tree = results.remove(max_ind).1.unwrap().1;

        for r in results.drain(..) {
            let t = r.1.unwrap().1;
            let records = r.0.iter().collect();
            if h_tree.consistent_with(&t) && h_tree.consistent_with_inserts(&t, &records) {
                h_tree.merge_consistent(&t, &records);
            } else {
                error!("Inconsistency detected between proofs when collecting");
            }
        }

        Ok(h_tree.tree)
    }

    async fn get_merkle_proof(
        &self,
        corenode_info: &DirectoryInfo,
        records: Vec<RecordID>,
    ) -> Result<(usize, DataTree), ClientError> {
        let mut connection = self
            .connector
            .connect(corenode_info.public(), &corenode_info.addr())
            .await?;

        let txr = TxRequest::GetProof(records);

        connection.send(&txr).await?;
        let resp = connection.receive::<TxResponse>().await?;
        match resp {
            TxResponse::GetProof(proof) => Ok(proof),
            _ => return Err(ReplyError::new().into()),
        }
    }

    pub async fn send_transaction_request<T: classic::Serialize>(
        &self,
        proof: DataTree,
        rule: RecordID,
        args: &T,
    ) -> Result<(), ClientError> {
        let rt = RuleTransaction::new(proof, rule, args);

        let exchanger = Exchanger::random();
        let connector = TcpConnector::new(exchanger);
        let mut connection = connector
            .connect(self.tob_info.public(), &self.tob_info.addr())
            .await?;

        let txr = TxRequest::Execute(rt);
        connection.send(&txr).await?;

        connection.receive::<TxResponse>().await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use super::super::test::*;
    use super::super::DataTree;

    use tracing::{trace_span};
    use tracing_futures::Instrument;

    #[tokio::test]
    async fn client_get_merkle_proofs() {
        init_logger();

        let mut t = DataTree::new();
        t.insert("Alan".to_string(), vec![0u8]);
        t.insert("Bob".to_string(), vec![1u8]);
        t.insert("Charlie".to_string(), vec![2u8]);

        let config = SetupConfig::setup(3, t.clone(), 10).await;
        let tob_info = &config.tob_info;
        let dir_info = &config.dir_info;

        async move {
            let client_node = ClientNode::new(tob_info, dir_info, 3)
                .await
                .expect("client node creation failed");

            debug!("client node created");

            let proof = client_node
                .get_merkle_proofs(vec![
                    "Alan".to_string(),
                    "Bob".to_string(),
                    "Charlie".to_string(),
                ])
                .await
                .expect("merkle proof error");

            assert!(t.get_validator().validate(&proof));
        }
        .instrument(trace_span!("get_merkle_proofs"))
        .await;

        config.tear_down().await;
    }

    #[tokio::test]
    async fn client_send_transaction_request() {
        init_logger();

        let filename =
            "contract_test/target/wasm32-wasi/release/contract_test.wasm";
        let rule_buffer =
            std::fs::read(filename).expect("could not load file into buffer");

        let mut t = DataTree::new();
        t.insert("Alice".to_string(), (1000i32).to_be_bytes().to_vec());
        t.insert("Bob".to_string(), (1000i32).to_be_bytes().to_vec());
        t.insert("transfer_rule".to_string(), rule_buffer);

        let config = SetupConfig::setup(1, t.clone(), 10).await;
        let tob_info = &config.tob_info;
        let dir_info = &config.dir_info;

        async move {
            let client_node = ClientNode::new(tob_info, dir_info, 1)
                .await
                .expect("client node creation failed");

            debug!("client node created");

            let proof = client_node
                .get_merkle_proofs(vec![
                    "Alice".to_string(),
                    "Bob".to_string(),
                    "transfer_rule".to_string(),
                ])
                .await
                .expect("merkle proof error");

            let args = ("Alice".to_string(), "Bob".to_string(), 50i32);
            client_node
                .send_transaction_request(
                    proof,
                    "transfer_rule".to_string(),
                    &args,
                )
                .await
                .expect("error sending request");

            // info!("Awaiting");
            // let _ = timeout(Duration::from_millis(2000), future::pending::<()>()).await;

            let result = client_node
                .get_merkle_proofs(vec!["Alice".to_string(), "Bob".to_string()])
                .await
                .expect("merkle proof error");

            let mut value_array = [0 as u8; 4];
            let v =
                &result.get(&"Alice".to_string()).unwrap()[..value_array.len()];
            value_array.copy_from_slice(v);
            assert_eq!(i32::from_be_bytes(value_array), 950);

            let mut value_array = [0 as u8; 4];
            let v =
                &result.get(&"Bob".to_string()).unwrap()[..value_array.len()];
            value_array.copy_from_slice(v);
            assert_eq!(i32::from_be_bytes(value_array), 1050);
        }
        .instrument(trace_span!("get_merkle_proofs"))
        .await;

        config.tear_down().await;
    }
}
