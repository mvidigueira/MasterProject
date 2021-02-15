use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use bls_amcl::common::{Params, SigKey, VerKey};
use bls_amcl::common::Keypair as BlsKeypair;

use drop::crypto::{
    key::exchange::{Exchanger, PublicKey, KeyPair as CommKeyPair},
    Digest,
};
use drop::net::{
    Connection, DirectoryInfo, Listener, ListenerError, TcpListener,
};
use rand::thread_rng;

use std::hash::{Hash, Hasher};

use super::{
    memory_usage::MemoryReport, CoreNodeError, DataTree, ExecuteResult, HTree,
    ModuleCache, Prefix, RecordID, RuleTransaction, TobRequest, TobResponse,
    Touch, UserCoreRequest, UserCoreResponse, SystemConfig
};
use wasm_common_bindings::Ledger;
use wasmer::{MemoryView, NativeFunc};

use futures::future::{self, Either};

use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::task;

use tracing::{error, info, trace_span};
use tracing_futures::Instrument;

const RECORD_LIMIT: usize = 400;

type ProtectedTree = Arc<RwLock<HTree>>;
type ProtectedModuleCache = Arc<RwLock<ModuleCache>>;

#[derive(Clone, PartialEq)]
pub struct Info {
    dir_info: DirectoryInfo,
    bls_pkey: VerKey,
}
impl Eq for Info {}
impl Hash for Info {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.dir_info.hash(state);
        self.bls_pkey.to_bytes().hash(state);
    }
}
impl Info {
    /// Get the `DirectoryInfo` contained in this `Info`
    pub fn bls_public(&self) -> &VerKey {
        &self.bls_pkey
    }

    /// Get the bls public key `VerKey` contained in this `Info`
    pub fn dir_info(&self) -> &DirectoryInfo {
        &self.dir_info
    }
}

pub struct CoreNode {
    listener: TcpListener,
    tob_pub_key: PublicKey,
    exit: Receiver<()>,

    bls_kp: BlsKeypair,

    data: ProtectedTree,
    module_cache: ProtectedModuleCache,

    corenodes_config: SystemConfig<Arc<DirectoryInfo>>,
}

impl CoreNode {
    pub async fn new(
        node_addr: SocketAddr,
        comm_kp: CommKeyPair,
        // bls_kp: BlsKeypair,

        tob_info: &DirectoryInfo,
        corenodes_config: SystemConfig<Arc<DirectoryInfo>>,

        dt: DataTree,
        history_len: usize,
        prefix_list: Vec<Prefix>,
    ) -> Result<(Self, Sender<()>), CoreNodeError> {
        let (tx, rx) = channel();

        let exchanger = Exchanger::new(comm_kp);

        let listener = TcpListener::new(node_addr, exchanger.clone())
            .await
            .expect("listen failed");

        let mut h_tree = HTree::new(history_len, prefix_list);

        for (k, v) in dt.clone_to_vec().drain(..) {
            h_tree.add_touch(&k);
            h_tree.insert(k, v);
        }
        h_tree.push_history();

        let params = Params::new("some publicly known string".as_bytes());
        let mut rng = thread_rng();
        let bls_kp = BlsKeypair::new(&mut rng, &params);

        let ret = (
            Self {
                listener: listener,
                tob_pub_key: *tob_info.public(),
                exit: rx,

                bls_kp: bls_kp,

                data: Arc::from(RwLock::new(h_tree)),
                module_cache: Arc::from(RwLock::new(ModuleCache::new())),

                corenodes_config: corenodes_config,
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

            let peer_pub = connection.remote_key();
            let data = self.data.clone();
            if peer_pub != Some(self.tob_pub_key) {
                info!("CLIENT connection {:?}", peer_pub);

                let module_cache = self.module_cache.clone();

                task::spawn(
                    async move {
                        let client_handler = ClientRequestHandler::new(
                            connection,
                            data,
                            module_cache,
                        );

                        if let Err(_) = client_handler.serve().await {
                            error!("failed request handling");
                        }
                    }
                    .instrument(trace_span!("client_request_receiver")),
                );
            } else {
                info!("TOB server connection: {:?}", peer_pub);

                task::spawn(
                    async move {
                        let request_handler =
                            TobRequestHandler::new(connection, data);

                        if let Err(_) = request_handler.serve().await {
                            error!("failed request handling");
                        }
                    }
                    .instrument(trace_span!("tob_request_receiver")),
                );
            }
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        self.listener.exchanger().keypair().public()
    }

    pub fn info(&self) -> Info {
        Info {
            dir_info: DirectoryInfo::from((
                *self.public_key(),
                self.listener.local_addr().unwrap(),
            )),
            bls_pkey: self.bls_kp.ver_key.clone(),
        }
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

struct ClientRequestHandler {
    connection: Connection,
    data: ProtectedTree,
    module_cache: ProtectedModuleCache,
}

impl ClientRequestHandler {
    fn new(
        connection: Connection,
        data: ProtectedTree,
        module_cache: ProtectedModuleCache,
    ) -> Self {
        Self {
            connection,
            data,
            module_cache,
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

        let history_count = guard.history_count;

        drop(guard);

        connection
            .send(&UserCoreResponse::GetProof((history_count, t)))
            .await?;

        Ok(())
    }

    fn execute_transaction(
        rule_id: &String,
        rule_hash: &Digest,
        args: &Vec<u8>,
        tree: &DataTree,
        module_cache: &mut ModuleCache,
        local_tree: &HTree,
    ) -> Result<Ledger, ()> {
        let instance =
            match module_cache.get_instance(rule_id, rule_hash, local_tree) {
                Err(e) => {
                    error!("Error getting module instance: {:?}", e);
                    return Err(());
                }
                Ok(i) => i,
            };

        let input_ledger: Ledger = tree.clone_to_vec().into_iter().collect();

        let allocate: NativeFunc<i32, i32> = match instance
            .exports
            .get_native_function("allocate_vec")
        {
            Err(e) => {
                error!("Error finding mandatory 'allocate_vec' function in wasm module: {:?}", e);
                return Err(());
            }
            Ok(alloc) => alloc,
        };

        let execute: NativeFunc<(i32, i32), i32> = match instance
            .exports
            .get_native_function("execute")
        {
            Err(e) => {
                error!("Error finding mandatory 'execute' function in wasm module: {:?}", e);
                return Err(());
            }
            Ok(exec) => exec,
        };

        let input = bincode::serialize(&(input_ledger, args.clone())).unwrap();
        let len = input.len();

        let ptr = match allocate.call(len as i32) {
            Ok(ptr) => ptr,
            Err(e) => {
                error!("Call to 'allocate' in wasm module failed: {:?}", e);
                return Err(());
            }
        };

        let mem = match instance.exports.get_memory("memory") {
            Ok(m) => m,
            Err(e) => {
                error!(
                    "Error finding default memory 'memory' wasm module: {:?}",
                    e
                );
                return Err(());
            }
        };

        let s: MemoryView<u8> = mem.view();

        for (i, v) in input.iter().enumerate() {
            s[ptr as usize + i].replace(*v);
        }

        let ptr = match execute.call(ptr, len as i32) {
            Ok(ptr) => ptr,
            Err(e) => {
                error!("Call to 'execute' in wasm module failed: {:?}", e);
                return Err(());
            }
        };
        let s: MemoryView<u8> = mem.view();

        let s = s[..].iter().map(|x| x.get()).collect::<Vec<u8>>();
        let output_ledger = match wasm_common_bindings::get_result(&s, ptr) {
            Err(_) => {
                error!("Error deserializing output from transaction.");
                return Err(());
            }
            Ok(l) => l,
        };

        info!("Execution successful, returning output_ledger");
        Ok(output_ledger)
    }

    async fn handle_execute(
        data: &mut ProtectedTree,
        module_cache: &mut ProtectedModuleCache,
        mut rt: RuleTransaction,
    ) -> Result<ExecuteResult, CoreNodeError> {
        let misc_digest =
            super::get_misc_digest(&rt.rule_version, &rt.rule_arguments);

        let used_record_count: usize = rt.merkle_proof.len();
        if used_record_count > RECORD_LIMIT {
            let cause = format!("Error processing transaction: record limit exceeded. Limit is {}, rule touches {}", RECORD_LIMIT, used_record_count);
            error!("{}", cause);
            return Ok(ExecuteResult::fail(
                rt.rule_record_id,
                rt.rule_version,
                misc_digest,
                cause,
            ));
        }

        let tree_guard = data.read().await;

        if !tree_guard
            .consistent_given_records(&rt.merkle_proof, &rt.touched_records)
        {
            let cause =
                format!("Error processing transaction: invalid merkle proof");
            error!("{}", cause);
            return Ok(ExecuteResult::fail(
                rt.rule_record_id,
                rt.rule_version,
                misc_digest,
                cause,
            ));
        }

        let mut cache_guard = module_cache.write().await;
        let res = ClientRequestHandler::execute_transaction(
            &rt.rule_record_id,
            &rt.rule_version,
            &rt.rule_arguments,
            &rt.merkle_proof,
            &mut cache_guard,
            &tree_guard,
        );
        drop(cache_guard);
        drop(tree_guard);

        match res {
            Err(_) => {
                return Ok(ExecuteResult::fail(
                    rt.rule_record_id,
                    rt.rule_version,
                    misc_digest,
                    format!("failed executing transaction : error message WIP"),
                ))
            }
            Ok(mut output_ledger) => {
                let mut output: Vec<(RecordID, Touch)> = vec![];

                let mut input_ledger: Ledger = rt
                    .merkle_proof
                    .clone_to_vec()
                    .into_iter()
                    .filter(|(k, _)| k != &rt.rule_record_id)
                    .collect();

                for k in rt.touched_records.drain(..) {
                    match (input_ledger.remove(&k), output_ledger.remove(&k)) {
                        (None, Some(v)) => {
                            output.push((k, Touch::Added(v)));
                        }
                        (None, None) => {
                            output.push((k, Touch::Read));
                        }
                        (Some(_), None) => {
                            output.push((k, Touch::Deleted));
                        }
                        (Some(v1), Some(v2)) => {
                            let v = if v1 == v2 {
                                Touch::Read
                            } else {
                                Touch::Modified(v2)
                            };

                            output.push((k, v));
                        }
                    }
                }

                output.sort_by(|x, y| x.0.cmp(&y.0));

                info!("Created response. Returning...");
                Ok(ExecuteResult::new(
                    rt.rule_record_id,
                    rt.rule_version,
                    misc_digest,
                    output,
                ))
            }
        }
    }

    async fn serve(mut self) -> Result<(), CoreNodeError> {
        while let Ok(txr) = self.connection.receive::<UserCoreRequest>().await {
            match txr {
                UserCoreRequest::GetProof(records) => {
                    info!("Received getproof request. Arguments {:?}", records);
                    let guard = self.data.read().await;
                    Self::handle_get_proof(
                        guard,
                        &mut self.connection,
                        records.clone(),
                    )
                    .await?;

                    info!(
                        "Replying to getproof request. Arguments {:?}",
                        records
                    );
                }
                UserCoreRequest::Execute(rt) => {
                    info!(
                        "Received execute request. Rule: {:#?}",
                        rt.rule_record_id
                    );

                    let result = Self::handle_execute(
                        &mut self.data,
                        &mut self.module_cache,
                        rt,
                    )
                    .await?;

                    info!(
                        "Replying to execute request. ExecuteResult: {:#?}",
                        result
                    );

                    self.connection
                        .send(&UserCoreResponse::Execute(result))
                        .await?;
                }
            }
        }

        self.connection.close().await?;

        info!("End of client connection");

        Ok(())
    }
}

struct TobRequestHandler {
    connection: Connection,
    data: ProtectedTree,
}

impl TobRequestHandler {
    fn new(connection: Connection, data: ProtectedTree) -> Self {
        Self { connection, data }
    }

    async fn serve(mut self) -> Result<(), CoreNodeError> {
        while let Ok(txr) = self.connection.receive::<TobRequest>().await {
            match txr {
                TobRequest::Apply(mut req) => {
                    let touched_records =
                        req.output.iter().map(|x| x.0.clone()).collect();

                    // TODO: receive and validate signatures here

                    let mut tree_guard = self.data.write().await;

                    if !tree_guard.consistent_given_records(
                        &req.input_merkle_proof,
                        &touched_records,
                    ) {
                        let cause = format!("Error processing transaction: invalid merkle proof");
                        error!("{}", cause);
                        continue;
                    }

                    tree_guard.merge_consistent(
                        &req.input_merkle_proof,
                        &touched_records,
                    );

                    for (k, t) in req.output.drain(..) {
                        match t {
                            Touch::Modified(v) | Touch::Added(v) => {
                                tree_guard.insert(k, v);
                            }
                            Touch::Deleted => {
                                tree_guard.remove(&k);
                            }
                            Touch::Read => (),
                        }
                    }

                    tree_guard.push_history();

                    // let (overhead, mut tree_size) =
                    let rep = MemoryReport::new(&tree_guard);
                    // This is excluding the memory occupied by the operation.
                    // This should be unnecessary once merkle tree memory usage is accurately determined.
                    // if rep.o_tree_serialized > bytes.len() {
                    //     rep.o_tree_serialized -= bytes.len();
                    // }
                    info!(
                        "Transaction applied: local data successfully updated.
                    {}",
                        rep
                    );
                }
            }
        }

        self.connection.close().await?;

        info!("end of TOB connection");

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::super::test::*;
    use super::super::{
        DataTree, TobRequest, TobResponse, UserCoreRequest, UserCoreResponse,
    };
    extern crate test;
    use super::*;
    use test::Bencher;
    use wasm_common_bindings::{ContextLedger, Ledger};

    use tracing::trace_span;
    use tracing_futures::Instrument;

    #[tokio::test]
    async fn corenode_shutdown() {
        init_logger();

        let fake_tob_addr = next_test_ip4();
        let exchanger = Exchanger::random();
        let fake_tob_info =
            DirectoryInfo::from((*exchanger.keypair().public(), fake_tob_addr));

        let (exit_tx, handle, _) = setup_corenode(
            next_test_ip4(),
            CommKeyPair::random(),
            &fake_tob_info,
            SystemConfig::new(vec!()),
            DataTree::new(),
            10,
            vec!["0"],
        )
        .await;

        wait_for_server(exit_tx, handle).await;
    }

    #[tokio::test]
    async fn corenode_getproof() {
        init_logger();

        let config =
            SetupConfig::setup(get_balanced_prefixes(1), DataTree::new(), 10)
                .await;

        let mut connection =
            create_peer_and_connect(&config.corenodes[0].2).await;

        let local = connection.local_addr().expect("getaddr failed");

        async move {
            let txr = UserCoreRequest::GetProof(vec![String::from("Alan")]);
            connection.send(&txr).await.expect("send failed");

            let resp = connection
                .receive::<UserCoreResponse>()
                .await
                .expect("recv failed");

            assert_eq!(
                resp,
                UserCoreResponse::GetProof((1, DataTree::new())),
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

        let config =
            SetupConfig::setup(get_balanced_prefixes(1), DataTree::new(), 10)
                .await;

        let mut c_node = create_peer_and_connect(&config.corenodes[0].2).await;
        let mut c_tob = create_peer_and_connect(&config.tob_info).await;

        let local = c_node.local_addr().expect("getaddr failed");

        async move {
            let txr = UserCoreRequest::GetProof(vec![String::from("Alan")]);
            c_node.send(&txr).await.expect("send failed");

            let resp = c_node
                .receive::<UserCoreResponse>()
                .await
                .expect("recv failed");

            assert_eq!(
                resp,
                UserCoreResponse::GetProof((1, DataTree::new())),
                "invalid response from corenode"
            );

            let txr = TobRequest::Apply(get_example_tobpayload());
            c_tob.send(&txr).await.expect("send failed");

            let resp =
                c_tob.receive::<TobResponse>().await.expect("recv failed");

            assert_eq!(
                resp,
                TobResponse::Result(String::from(
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

    // fn handle_execute(
    //     htree: &mut HTree,
    //     rt: &RuleTransaction,
    // ) -> Result<(), CoreNodeError> {
    //     let used_record_count: usize = rt.merkle_proof.len();
    //     if used_record_count > RECORD_LIMIT {
    //         panic!("Error processing transaction: record limit exceeded. Limit is {}, rule touches {}", RECORD_LIMIT, used_record_count);
    //     }

    //     if rt.touched_records.len() > RECORD_LIMIT {
    //         panic!("Error processing transaction: record limit exceeded. Limit is {}, rule touches {}", RECORD_LIMIT, rt.touched_records.len());
    //     }

    //     if !htree
    //         .consistent_given_records(&rt.merkle_proof, &rt.touched_records)
    //     {
    //         panic!("Error processing transaction: invalid merkle proof");
    //     }

    //     match rt.merkle_proof.get(&rt.rule_record_id) {
    //         Err(_) => {
    //             panic!("Error processing transaction: rule is missing from merkle proof");
    //         }
    //         Ok(bytes) => {
    //             let mut contract = match WasmContract::load_bytes(bytes) {
    //                 Err(e) => {
    //                     panic!("Error processing transaction: error loading wasi contract: {:?}", e);
    //                 }
    //                 Ok(c) => c,
    //             };

    //             let args = rain_wasi_common::serialize_args_from_byte_vec(
    //                 &rt.rule_arguments,
    //             );

    //             // removes (k,v) association of rule, for performance
    //             let input_ledger: Ledger = rt
    //                 .merkle_proof
    //                 .clone_to_vec()
    //                 .into_iter()
    //                 .filter(|(k, _)| k != &rt.rule_record_id)
    //                 .collect();

    //             // Execute the transaction in the wasm runtime
    //             let result =
    //                 &contract.execute(input_ledger.serialize_wasi(), args);

    //             // // Execute the transaction in the wasm runtime
    //             // let result =
    //             //     &self.simulate_transaction(input_ledger.serialize_wasi(), args);

    //             // Extract the result
    //             let _ = match rain_wasi_common::extract_result(result) {
    //                 Err(e) => {
    //                     panic!("Error processing transaction: contract output an error: {}", e);
    //                 }
    //                 Ok(l) => l,
    //             };

    //             htree.merge_consistent(&rt.merkle_proof, &rt.touched_records);
    //         }
    //     }

    //     Ok(())
    // }

    // #[bench]
    // fn bench_handle_execute(b: &mut Bencher) {
    //     let filename =
    //         "contract_test/target/wasm32-wasi/release/contract_test.wasm";
    //     let rule_buffer =
    //         std::fs::read(filename).expect("could not load file into buffer");

    //     let mut t = DataTree::new();
    //     let records = [
    //         "Alice", "Bob", "Charlie", "Dave", "Aaron", "Vanessa", "Justin",
    //         "Irina",
    //     ];
    //     for &k in records.iter() {
    //         t.insert(String::from(k), (1000i32).to_be_bytes().to_vec());
    //     }
    //     t.insert("transfer_rule".to_string(), rule_buffer);

    //     let mut h_tree = HistoryTree::new(
    //         5,
    //         vec![]
    //     );

    //     for (k, v) in t.clone_to_vec().drain(..) {
    //         h_tree.add_touch(&k);
    //         h_tree.insert(k, v);
    //     }
    //     h_tree.push_history();

    //     let records = vec![
    //         "Alice".to_string(),
    //         "Bob".to_string(),
    //     ];

    //     let proof = get_proof_for_records(&h_tree, records.clone());
    //     let args = ("Alice".to_string(), "Bob".to_string(), 50i32);

    //     let rt = RuleTransaction::new(
    //         proof,
    //         "transfer_rule".to_string(),
    //         records,
    //         &args,
    //     );

    //     b.iter(|| handle_execute(&mut h_tree, &rt));
    // }
}
