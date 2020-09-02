use std::net::SocketAddr;
use std::sync::Arc;

use drop::crypto::{self, key::exchange::{Exchanger, PublicKey}, Digest};
use drop::net::{
    Connection, DirectoryListener, Listener, ListenerError, TcpConnector,
    TcpListener, DirectoryInfo, DirectoryConnector,
};

use super::{
    DataTree, RecordID, RecordVal, RuleTransaction, TxRequest, TxResponse,
};

use super::CoreNodeError;
use super::history_tree::HistoryTree;

use futures::future::{self, Either};

use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::task;

use tracing::{error, info, trace_span};
use tracing_futures::Instrument;

use rain_wasi_common::{Ledger, WasiSerializable};
use rain_wasmtime_contract::WasmContract;

use super::simulated_contract;

use std::mem;

const RECORD_LIMIT: usize = 400;

type HTree = HistoryTree<RecordID, RecordVal>;

impl HTree {
    pub fn memory_usage(&self) -> (usize, usize) {
        let mut overhead: usize = 0;

        overhead += mem::size_of::<HTree>();

        for k in &self.touches {
            overhead += k.len() * mem::size_of::<Arc<RecordID>>();
        }
        overhead += &self.counts.len() * mem::size_of::<Arc<RecordID>>();
        for k in &self.counts {
            overhead += (**k).len();
        }
        overhead += &self.history.len() * mem::size_of::<Digest>();
        overhead += &self.d_list.len() * mem::size_of::<Digest>();

        (overhead, bincode::serialize(&self.tree).unwrap().len())
    }
}

type ProtectedTree = Arc<RwLock<HTree>>;

pub struct CoreNode {
    dir_listener: DirectoryListener,
    tob_addr: SocketAddr,
    exit: Receiver<()>,

    data: ProtectedTree,
}

impl CoreNode {
    pub async fn new(
        node_addr: SocketAddr,
        dir_info: &DirectoryInfo,
        tob_addr: SocketAddr,
        nr_peer: usize,
        dt: DataTree,
        history_len: usize,
    ) -> Result<(Self, Sender<()>), CoreNodeError> {
        let (tx, rx) = channel();

        let exchanger = Exchanger::random();

        let listener = TcpListener::new(node_addr, exchanger.clone())
            .await
            .expect("listen failed");

        let connector = TcpConnector::new(exchanger.clone());
        let dir_listener =
            DirectoryListener::new(listener, connector, dir_info.addr()).await?;

        let connector = TcpConnector::new(exchanger.clone());
        let mut dir_connector = DirectoryConnector::new(connector);
        let mut peers = if nr_peer > 0 {
            dir_connector
                .wait(nr_peer, dir_info)
                .await
                .expect("could not wait")
        } else {
            Vec::new()
        };

        let mut h_tree = HistoryTree::new(history_len,
            crypto::hash(exchanger.keypair().public()).unwrap(), 
            peers.drain(..).map(|info| crypto::hash(info.public()).unwrap()).collect(),
        );

        for (k,v) in dt.clone_to_vec().drain(..) {
            h_tree.add_touch(&k);
            h_tree.insert(k, v);
        }
        h_tree.push_history();

        let ret = (
            Self {
                dir_listener: dir_listener,
                tob_addr: tob_addr,
                exit: rx,

                data: Arc::from(RwLock::new(h_tree)),
            },
            tx,
        );

        Ok(ret)
    }

    // handle this better, don't use an all encompassing error
    pub async fn serve(mut self) -> Result<(), CoreNodeError> {
        let mut exit_fut = Some(self.exit);

        loop {
            let (exit, connection) = match Self::poll_incoming(
                &mut self.dir_listener,
                exit_fut.take().unwrap(),
            )
            .await
            {
                PollResult::Error(e) => {
                    error!("failed to accept incoming connection: {}", e);
                    return Err(e.into());
                }
                PollResult::Exit => {
                    info!("directory server exiting...");
                    return Ok(());
                }
                PollResult::Incoming(exit, connection) => (exit, connection),
            };

            exit_fut = Some(exit);

            let peer_addr = connection.peer_addr()?;

            let data = self.data.clone();

            if peer_addr == self.tob_addr {
                info!(
                    "new directory connection from TOB server: {}",
                    peer_addr
                );
            } else {
                info!("new directory connection from client {}", peer_addr);
            }

            let from_client = peer_addr != self.tob_addr;
            task::spawn(
                async move {
                    let request_handler = TxRequestHandler::new(connection, data, from_client);

                    if let Err(_) = request_handler.serve().await {
                        error!("failed request handling");
                    }

                }.instrument(trace_span!("tob_request_receiver", client = %self.tob_addr)),
            );
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        self.dir_listener.exchanger().keypair().public()
    }

    async fn poll_incoming(
        dir_listener: &mut DirectoryListener,
        exit: Receiver<()>,
    ) -> PollResult {
        match future::select(exit, dir_listener.accept()).await {
            Either::Left(_) => PollResult::Exit,
            Either::Right((Ok(connection), exit)) => {
                PollResult::Incoming(exit, connection)
            }
            Either::Right((Err(e), _)) => PollResult::Error(e),
        }
    }
}

enum PollResult {
    Incoming(Receiver<()>, Connection),
    Error(ListenerError),
    Exit,
}

struct TxRequestHandler {
    connection: Connection,
    data: ProtectedTree,
    from_client: bool,
}

impl TxRequestHandler {
    fn new(
        connection: Connection,
        data: ProtectedTree,
        from_client: bool,
    ) -> Self {
        Self {
            connection,
            data,
            from_client,
        }
    }

    async fn handle_get_proof(
        &mut self,
        records: Vec<RecordID>,
    ) -> Result<(), CoreNodeError> {
        let guard = self.data.read().await;

        let mut t = guard.get_validator();
        for r in records {
            match guard.get_proof_with_placeholder(&r) {
                Ok(proof) => {
                    t.merge(&proof).unwrap();
                }
                Err(_) => (),
            }
        }

        self.connection.send(&TxResponse::GetProof((guard.history_count, t))).await?;

        drop(guard);

        Ok(())
    }

    async fn handle_execute(
        &mut self,
        rt: RuleTransaction,
    ) -> Result<(), CoreNodeError> {
        let used_record_count: usize = rt.merkle_proof.len();
        if used_record_count > RECORD_LIMIT {
            error!("Error processing transaction: record limit exceeded. Limit is {}, rule touches {}", RECORD_LIMIT, used_record_count);
            return Ok(());
        }

        let mut guard = self.data.write().await;
        
        if rt.touched_records.len() > RECORD_LIMIT {
            error!("Error processing transaction: record limit exceeded. Limit is {}, rule touches {}", RECORD_LIMIT, rt.touched_records.len());
            return Ok(());
        }            

        if !guard.consistent_given_records(&rt.merkle_proof, &rt.touched_records) {
            error!("Error processing transaction: invalid merkle proof");
            return Ok(());            
        }
        

        match rt.merkle_proof.get(&rt.rule_record_id) {
            Err(_) => {
                error!("Error processing transaction: rule is missing from merkle proof");
                return Ok(());
            }
            Ok(bytes) => {
                let mut contract = match WasmContract::load_bytes(bytes) {
                    Err(e) => {
                        error!("Error processing transaction: error loading wasi contract: {:?}", e);
                        return Ok(());
                    }
                    Ok(c) => c,
                };

                let args = rain_wasi_common::serialize_args_from_byte_vec(
                    &rt.rule_arguments,
                );

                // removes (k,v) association of rule, for performance
                let mut input_ledger: Ledger =
                    rt.merkle_proof.clone_to_vec().into_iter().filter(|(k, _)| k != &rt.rule_record_id).collect();

                // Execute the transaction in the wasm runtime
                let result =
                    &contract.execute(input_ledger.serialize_wasi(), args);

                // // Execute the transaction in the wasm runtime
                // let result =
                //     &self.simulate_transaction(input_ledger.serialize_wasi(), args);                

                // Extract the result
                let mut output_ledger = match rain_wasi_common::extract_result(
                    result,
                ) {
                    Err(e) => {
                        error!("Error processing transaction: contract output an error: {}", e);
                        return Ok(());
                    }
                    Ok(l) => l,
                };

                guard.merge_consistent(&rt.merkle_proof, &rt.touched_records);

                for (k, v) in output_ledger.drain() {
                    match input_ledger.remove(&k) {
                        None => {
                            //info!("Inserted {:?} into data tree.", (k.clone(), v.clone()));
                            guard.insert(k, v);
                        }
                        Some(v2) if v != v2 => {
                            //info!("Inserted {:?} into data tree.", (k.clone(), v.clone()));
                            guard.insert(k, v);
                        }
                        _ => (),
                    }
                }

                // check that this is working correctly
                for (k, _) in input_ledger.drain() {
                    info!("Removed {:?} from data tree.", k);
                    guard.remove(&k);
                }

                guard.push_history();
                
                let (overhead, mut tree_size) = guard.memory_usage();
                if tree_size > bytes.len() {
                    tree_size -= bytes.len();
                }
                info!("Transaction applied: local data successfully updated. Overhead: {}, Data: {}", overhead, tree_size);
            }
        }

        drop(guard);

        Ok(())
    }

    fn simulate_transaction(&self, ledger: String, args: String) -> String {
        // simulated_contract::execute(ledger, args)
        simulated_contract::set_record_value(ledger, args)
    }

    async fn serve(mut self) -> Result<(), CoreNodeError> {
        while let Ok(txr) = self.connection.receive::<TxRequest>().await {
            match txr {
                TxRequest::GetProof(records) => {
                    info!(
                        "Received getproof request. Arguments {:?}",
                        records
                    );

                    // if self.from_client {
                    self.handle_get_proof(records.clone()).await?;
                    // } else {
                    //     error!("TxRequest::GetProof should be sent directly by a client, not via TOB!");
                    // }

                    info!(
                        "Replying to getproof request. Arguments {:?}",
                        records
                    );
                }
                TxRequest::Execute(rt) => {
                    info!(
                        "Received execute request. Rule: {:#?}",
                        rt.rule_record_id
                    );

                    // if self.from_client {
                    //     error!("Client attempting to execute directly. TxExecute can only come from TOB!");
                    // } else {
                    self.handle_execute(rt).await?;
                    // }
                }
            }
        }

        self.connection.close().await?;

        if self.from_client {
            info!("end of client connection");
        } else {
            info!("end of TOB connection");
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::super::test::*;
    use super::super::{DataTree, TxRequest, TxResponse};

    use tracing::trace_span;
    use tracing_futures::Instrument;

    #[tokio::test]
    async fn corenode_shutdown() {
        init_logger();

        let (exit_dir, handle_dir, dir_info) = setup_dir(next_test_ip4()).await;

        let fake_tob_addr = next_test_ip4();

        let (exit_tx, handle, _) = setup_corenode(
            next_test_ip4(),
            &dir_info,
            fake_tob_addr,
            1,
            DataTree::new(),
            10,
        )
        .await;

        wait_for_server(exit_tx, handle).await;
        wait_for_server(exit_dir, handle_dir).await;
    }

    #[tokio::test]
    async fn corenode_getproof() {
        init_logger();

        let config = SetupConfig::setup(1, DataTree::new(), 10).await;

        let mut connection =
            create_peer_and_connect(&config.corenodes[0].2).await;

        let local = connection.local_addr().expect("getaddr failed");

        async move {
            let txr = TxRequest::GetProof(vec![String::from("Alan")]);
            connection.send(&txr).await.expect("send failed");

            let resp = connection
                .receive::<TxResponse>()
                .await
                .expect("recv failed");

            assert_eq!(
                resp,
                TxResponse::GetProof((1, DataTree::new().get_validator())),
                "invalid response from corenode"
            );
        }
        .instrument(trace_span!("get_proof", client = %local))
        .await;

        config.tear_down().await;
    }

    // move this test to integration tests or client
    #[tokio::test]
    async fn request_add() {
        init_logger();

        let config = SetupConfig::setup(1, DataTree::new(), 10).await;

        let mut c_node = create_peer_and_connect(&config.corenodes[0].2).await;
        let mut c_tob = create_peer_and_connect(&config.tob_info).await;

        let local = c_node.local_addr().expect("getaddr failed");

        async move {
            let txr = TxRequest::GetProof(vec![String::from("Alan")]);
            c_node.send(&txr).await.expect("send failed");

            let resp =
                c_node.receive::<TxResponse>().await.expect("recv failed");

            assert_eq!(
                resp,
                TxResponse::GetProof((1, DataTree::new().get_validator())),
                "invalid response from corenode"
            );

            let txr = TxRequest::Execute(get_example_rt());
            c_tob.send(&txr).await.expect("send failed");

            let resp =
                c_tob.receive::<TxResponse>().await.expect("recv failed");

            assert_eq!(
                resp,
                TxResponse::Execute(String::from(
                    "Request successfully forwarded to all peers"
                )),
                "invalid response from tob server"
            );

            let _ = c_tob.close().await;
            let _ = c_node.close().await;
        }
        .instrument(trace_span!("request_add", client = %local))
        .await;

        config.tear_down().await;
    }
}
