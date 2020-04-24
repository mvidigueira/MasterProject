use std::net::SocketAddr;
use std::collections::HashMap;

use drop::crypto::key::exchange::{Exchanger};
use drop::crypto::{self, Digest};
use drop::net::{Connector, DirectoryConnector, DirectoryInfo, TcpConnector,
};

use super::{TxRequest, TxResponse, RecordID, DataTree, closest};

use super::{ClientError, ReplyError};

use futures::future;

pub struct ClientNode {
    corenodes: Vec<(Digest, DirectoryInfo)>,
    connector: TcpConnector,
    tob_addr: SocketAddr,
}

impl ClientNode {
    pub async fn new(
        tob_addr: SocketAddr,
        dir_info: &DirectoryInfo,
        nr_peer: usize,
    ) -> Result<Self, ClientError> {
        let exchanger = Exchanger::random();

        let connector = TcpConnector::new(exchanger.clone());
        let mut dir_connector = DirectoryConnector::new(connector);
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
                tob_addr: tob_addr,
        };

        Ok(ret)
    }

    pub async fn get_merkle_proofs(&self, records: Vec<RecordID>) -> Result<DataTree, ClientError> {
        let mut m: HashMap<DirectoryInfo, Vec<RecordID>> = HashMap::new();

        for r_id in records {
            let info = closest(&self.corenodes, &r_id);
            if !m.contains_key(info) {
                m.insert(info.clone(), Vec::new());
            }
            m.get_mut(info).unwrap().push(r_id);
        }

        let results = future::join_all(
            m.drain().map(|(k, v)| async move { self.get_merkle_proof(&k, v).await })
        )
        .await;

        let mut dt_o: Option<DataTree> = None;
        for r in results {
            let t = r?;
            dt_o = match dt_o {
                None => Some(t),
                Some(mut dt) => {
                    dt.merge(&t)?;
                    Some(dt)
                }
            }
        }

        match dt_o {
            Some(dt) => Ok(dt),
            None =>  { unreachable!(); },
        }
    }

    async fn get_merkle_proof(&self, corenode_info: &DirectoryInfo, records: Vec<RecordID>) -> Result<DataTree, ClientError> {
        let mut connection = self.connector.connect(corenode_info.public(), &corenode_info.addr()).await?;

        let txr = TxRequest::GetProof(records);

        connection.send(&txr).await?;
        let resp = connection.receive::<TxResponse>().await?;
        match resp {
            TxResponse::GetProof(proof) => Ok(proof),
            _ => { return Err(ReplyError::new().into()) }
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    use super::super::test::*;
    use super::super::{DataTree};

    #[tokio::test]
    async fn client_get_merkle_proofs() {
        init_logger();

        let mut t = DataTree::new();
        t.insert("Alan".to_string(), vec!(0u8));
        t.insert("Bob".to_string(), vec!(1u8));
        t.insert("Charlie".to_string(), vec!(2u8));

        let config = SetupConfig::setup(3, t.clone()).await;

        let client_node = ClientNode::new(config.tob_info.addr(), &config.dir_info, 3).await.expect("client node creation failed");
        let proof = client_node.get_merkle_proofs(
            vec!("Alan".to_string(), "Bob".to_string(), "Charlie".to_string())
        )
        .await
        .expect("merkle proof erros");

        assert!(t.get_validator().validate(&proof));

        config.tear_down().await;
    }
}