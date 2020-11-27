use std::net::SocketAddr;
use std::sync::Arc;

use drop::crypto::{
    key::exchange::{Exchanger, PublicKey},
    Digest,
};
use drop::net::{
    Connection, DirectoryInfo, Listener,
    ListenerError, TcpListener,
};

use super::{
    DataTree, RecordID, RecordVal, RuleTransaction, TxRequest, TxResponse,
};

use super::history_tree::{HistoryTree, Prefix};
use super::CoreNodeError;

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

pub struct MemoryReport {
    pub o_h_tree: usize, 
    pub o_touches_queue: usize,
    pub o_touches_hashset: usize, 
    pub o_touches_data: usize,
    pub o_history_queue: usize,
    pub o_prefix_list: usize,
    pub o_tree_serialized: usize,
}

impl std::fmt::Display for MemoryReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let o_sum_data_independent = self.o_h_tree + self.o_touches_queue + 
        self.o_touches_hashset + self.o_touches_data + 
        self.o_history_queue + self.o_prefix_list;

        write!(f, "Memory usage decomposition:
        - History tree ------------------------ {} B
          - Touched records queue: ------------ {} B
          - Touched records hashset: ---------- {} B
          - Touched records data: ------------- {} B
          - Tree root history queue: ---------- {} B
          - Prefix list ----------------------- {} B
        Data independent overhead total: ------ {} B
          - Merkle tree (serialized) ---------- {} B
        
        Total memory: ------------------------- {} B",
        self.o_h_tree, 
        self.o_touches_queue,
        self.o_touches_hashset, 
        self.o_touches_data,
        self.o_history_queue,
        self.o_prefix_list, 
        o_sum_data_independent, 
        self.o_tree_serialized, 
        o_sum_data_independent + self.o_tree_serialized)
    }
}


impl HTree {
    pub fn memory_usage_report(&self) -> MemoryReport {
        let o_h_tree = mem::size_of::<HTree>();
        let mut o_touches_queue = 0;
        for k in &self.touches {
            o_touches_queue += k.len() * mem::size_of::<Arc<RecordID>>();
        }
        let o_touches_hashset = &self.counts.len() * mem::size_of::<Arc<RecordID>>();
        let mut o_touches_data = 0;
        for k in &self.counts {
            o_touches_data += (**k).len();
        }
        let o_history_queue = &self.history.len() * mem::size_of::<Digest>();
        let o_prefix_list = &self.prefix_list.len() * mem::size_of::<Prefix>();

        let o_tree_serialized = bincode::serialize(&self.tree).unwrap().len();

        MemoryReport{ 
            o_h_tree, 
            o_touches_queue,
            o_touches_hashset, 
            o_touches_data,
            o_history_queue,
            o_prefix_list, 
            o_tree_serialized,
        }
    }
}

type ProtectedTree = Arc<RwLock<HTree>>;

pub struct CoreNode {
    listener: TcpListener,
    tob_addr: SocketAddr,
    tob_pub_key: PublicKey,
    exit: Receiver<()>,

    data: ProtectedTree,
}

impl CoreNode {
    pub async fn new(
        node_addr: SocketAddr,
        tob_info: &DirectoryInfo,
        dt: DataTree,
        history_len: usize,
        prefix_list: Vec<Prefix>,
    ) -> Result<(Self, Sender<()>), CoreNodeError> {
        let (tx, rx) = channel();

        let exchanger = Exchanger::random();

        let listener = TcpListener::new(node_addr, exchanger.clone())
            .await
            .expect("listen failed");

        // let connector = TcpConnector::new(exchanger.clone());
        // let dir_listener =
        //     DirectoryListener::new(listener, connector, dir_info.addr())
        //         .await?;

        let mut h_tree = HistoryTree::new(
            history_len,
            prefix_list,
        );

        for (k, v) in dt.clone_to_vec().drain(..) {
            h_tree.add_touch(&k);
            h_tree.insert(k, v);
        }
        h_tree.push_history();

        let ret = (
            Self {
                listener: listener,
                tob_addr: tob_info.addr(),
                tob_pub_key: *tob_info.public(),
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
                &mut self.listener,
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
            let peer_pub = connection.remote_key();

            let data = self.data.clone();

            if peer_pub == Some(self.tob_pub_key) {
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
        self.listener.exchanger().keypair().public()
    }

    async fn poll_incoming(
        listener: &mut TcpListener,
        exit: Receiver<()>,
    ) -> PollResult {
        match future::select(exit, listener.accept()).await {
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
        guard: tokio::sync::RwLockReadGuard<'_, HTree>,
        connection: &mut Connection,
        records: Vec<RecordID>,
    ) -> Result<(), CoreNodeError> {
        let mut t = guard.get_validator();

        for r in records {
            match guard.get_proof_with_placeholder(&r) {
                Ok(proof) => {
                    t.merge(&proof).unwrap();
                }
                Err(_) => (),
            }
        }

        connection
            .send(&TxResponse::GetProof((guard.history_count, t)))
            .await?;

        drop(guard);

        Ok(())
    }

    async fn handle_execute(
        data: &mut ProtectedTree,
        rt: RuleTransaction,
    ) -> Result<(), CoreNodeError> {
        let used_record_count: usize = rt.merkle_proof.len();
        if used_record_count > RECORD_LIMIT {
            error!("Error processing transaction: record limit exceeded. Limit is {}, rule touches {}", RECORD_LIMIT, used_record_count);
            return Ok(());
        }

        let mut guard = data.write().await;

        if rt.touched_records.len() > RECORD_LIMIT {
            error!("Error processing transaction: record limit exceeded. Limit is {}, rule touches {}", RECORD_LIMIT, rt.touched_records.len());
            return Ok(());
        }

        if !guard
            .consistent_given_records(&rt.merkle_proof, &rt.touched_records)
        {
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
                        return Ok(()); // refactor: change this to Err
                    }
                    Ok(c) => c,
                };

                let args = rain_wasi_common::serialize_args_from_byte_vec(
                    &rt.rule_arguments,
                );

                // removes (k,v) association of rule, for performance
                let mut input_ledger: Ledger = rt
                    .merkle_proof
                    .clone_to_vec()
                    .into_iter()
                    .filter(|(k, _)| k != &rt.rule_record_id)
                    .collect();

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
                        // new (k,v)
                        None => {
                            //info!("Inserted {:?} into data tree.", (k.clone(), v.clone()));
                            guard.insert(k, v);
                        }
                        // modified (k,v)
                        Some(v2) if v != v2 => {
                            //info!("Inserted {:?} into data tree.", (k.clone(), v.clone()));
                            guard.insert(k, v);
                        }
                        _ => (),
                    }
                }

                for (k, _) in input_ledger.drain() {
                    //info!("Removed {:?} from data tree.", k);
                    guard.remove(&k);
                }

                guard.push_history();

                // let (overhead, mut tree_size) =
                let mut rep = guard.memory_usage_report();
                // This is excluding the memory occupied by the operation.
                // This should be unnecessary once merkle tree memory usage is accurately determined.
                if rep.o_tree_serialized > bytes.len() {
                    rep.o_tree_serialized -= bytes.len();
                }
                info!("Transaction applied: local data successfully updated.
                {}", rep);
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
                    info!("Received getproof request. Arguments {:?}", records);

                    // if self.from_client {
                    let guard = self.data.read().await;
                    Self::handle_get_proof(
                        guard,
                        &mut self.connection,
                        records.clone(),
                    )
                    .await?;
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
                    TxRequestHandler::handle_execute(&mut self.data, rt)
                        .await?;
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

        let fake_tob_addr = next_test_ip4();
        let exchanger = Exchanger::random();
        let fake_tob_info = DirectoryInfo::from((*exchanger.keypair().public(), fake_tob_addr));

        let (exit_tx, handle, _) = setup_corenode(
            next_test_ip4(),
            &fake_tob_info,
            DataTree::new(),
            10,
            vec!("0"),
        )
        .await;

        wait_for_server(exit_tx, handle).await;
    }

    #[tokio::test]
    async fn corenode_getproof() {
        init_logger();

        let config = SetupConfig::setup(get_balanced_prefixes(1), DataTree::new(), 10).await;

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
                TxResponse::GetProof((1, DataTree::new())),
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

        let config = SetupConfig::setup(get_balanced_prefixes(1), DataTree::new(), 10).await;

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
                TxResponse::GetProof((1, DataTree::new())),
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

    extern crate test;
    use test::Bencher;

    use super::*;

    fn get_proof_for_records(data: &HTree, records: Vec<RecordID>) -> DataTree {
        let mut t = data.get_validator();
        for r in records {
            match data.get_proof_with_placeholder(&r) {
                Ok(proof) => {
                    t.merge(&proof).unwrap();
                }
                Err(_) => (),
            }
        }

        t
    }

    fn handle_execute(
        htree: &mut HTree,
        rt: &RuleTransaction,
    ) -> Result<(), CoreNodeError> {
        let used_record_count: usize = rt.merkle_proof.len();
        if used_record_count > RECORD_LIMIT {
            panic!("Error processing transaction: record limit exceeded. Limit is {}, rule touches {}", RECORD_LIMIT, used_record_count);
        }

        if rt.touched_records.len() > RECORD_LIMIT {
            panic!("Error processing transaction: record limit exceeded. Limit is {}, rule touches {}", RECORD_LIMIT, rt.touched_records.len());
        }

        if !htree
            .consistent_given_records(&rt.merkle_proof, &rt.touched_records)
        {
            panic!("Error processing transaction: invalid merkle proof");
        }

        match rt.merkle_proof.get(&rt.rule_record_id) {
            Err(_) => {
                panic!("Error processing transaction: rule is missing from merkle proof");
            }
            Ok(bytes) => {
                let mut contract = match WasmContract::load_bytes(bytes) {
                    Err(e) => {
                        panic!("Error processing transaction: error loading wasi contract: {:?}", e);
                    }
                    Ok(c) => c,
                };

                let args = rain_wasi_common::serialize_args_from_byte_vec(
                    &rt.rule_arguments,
                );

                // removes (k,v) association of rule, for performance
                let input_ledger: Ledger = rt
                    .merkle_proof
                    .clone_to_vec()
                    .into_iter()
                    .filter(|(k, _)| k != &rt.rule_record_id)
                    .collect();

                // Execute the transaction in the wasm runtime
                let result =
                    &contract.execute(input_ledger.serialize_wasi(), args);

                // // Execute the transaction in the wasm runtime
                // let result =
                //     &self.simulate_transaction(input_ledger.serialize_wasi(), args);

                // Extract the result
                let _ = match rain_wasi_common::extract_result(result) {
                    Err(e) => {
                        panic!("Error processing transaction: contract output an error: {}", e);
                    }
                    Ok(l) => l,
                };

                htree.merge_consistent(&rt.merkle_proof, &rt.touched_records);
            }
        }

        Ok(())
    }

    #[bench]
    fn bench_handle_execute(b: &mut Bencher) {
        let filename =
            "contract_test/target/wasm32-wasi/release/contract_test.wasm";
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
        t.insert("transfer_rule".to_string(), rule_buffer);

        let mut h_tree = HistoryTree::new(
            5,
            vec![]
        );

        for (k, v) in t.clone_to_vec().drain(..) {
            h_tree.add_touch(&k);
            h_tree.insert(k, v);
        }
        h_tree.push_history();

        let records = vec![
            "Alice".to_string(),
            "Bob".to_string(),
            "transfer_rule".to_string(),
        ];

        let proof = get_proof_for_records(&h_tree, records.clone());
        let args = ("Alice".to_string(), "Bob".to_string(), 50i32);

        let rt = RuleTransaction::new(
            proof,
            "transfer_rule".to_string(),
            records,
            &args,
        );

        b.iter(|| handle_execute(&mut h_tree, &rt));
    }
}
