use std::net::SocketAddr;
use std::sync::Arc;

use super::{
    BlsKeypair, BlsParams, BlsSigInfo, BlsSigKey, BlsSignature, BlsVerKey,
    BlsVerifySignatures,
};

use drop::crypto::{
    key::exchange::{Exchanger, KeyPair as CommKeyPair, PublicKey},
    Digest,
};
use drop::net::{
    Connection, DirectoryInfo, Listener, ListenerError, TcpListener,
};

use std::hash::{Hash, Hasher};

use super::{
    memory_usage::MemoryReport, CoreNodeError, DataTree, ExecuteResult, HTree,
    PayloadForTob, Prefix, RecordID, RuleTransaction, SystemConfig, TobRequest,
    Touch, UserCoreRequest, UserCoreResponse,
};
use crate::utils::ModuleCache;
use wasm_common_bindings::Ledger;
use wasmer::{MemoryView, NativeFunc};

use futures::future::{self, Either};
use futures::stream::StreamExt;
use futures::Stream;

use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::task;

use tracing::{error, info, trace_span};
use tracing_futures::Instrument;

const RECORD_LIMIT: usize = 400;

type ProtectedTree = Arc<RwLock<HTree>>;
type ProtectedModuleCache = Arc<RwLock<ModuleCache<RecordID>>>;
type SharedConfig = Arc<SystemConfig<Arc<Info>>>;

#[derive(Clone, PartialEq)]
pub struct Info {
    dir_info: DirectoryInfo,
    bls_pkey: BlsVerKey,
}
impl Eq for Info {}
impl Hash for Info {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.dir_info.hash(state);
        self.bls_pkey.to_bytes().hash(state);
    }
}
impl Info {
    /// Create a new 'Info' from a 'DirectoryInfo' and a bls public key
    pub fn new(dir_info: DirectoryInfo, bls_pkey: BlsVerKey) -> Self {
        Self { dir_info, bls_pkey }
    }

    /// Get the `DirectoryInfo` contained in this `Info`
    pub fn bls_public(&self) -> &BlsVerKey {
        &self.bls_pkey
    }

    /// Get the bls public key `VerKey` contained in this `Info`
    pub fn dir_info(&self) -> &DirectoryInfo {
        &self.dir_info
    }
}

pub struct CoreNode {
    listener: TcpListener,
    exit: Receiver<()>,

    bls_kp: BlsKeypair,

    data: ProtectedTree,
    module_cache: ProtectedModuleCache,

    corenodes_config: SharedConfig,
}

impl CoreNode {
    pub async fn new<T: Stream<Item = TobRequest> + Send + Unpin + 'static>(
        node_addr: SocketAddr,
        comm_kp: CommKeyPair,
        bls_kp: BlsKeypair,

        tob_stream: T,
        corenodes_config: SystemConfig<Arc<Info>>,

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

        let ret = (
            Self {
                listener: listener,
                exit: rx,

                bls_kp: bls_kp,

                data: Arc::from(RwLock::new(h_tree)),
                module_cache: Arc::from(RwLock::new(ModuleCache::new())),

                corenodes_config: Arc::new(corenodes_config),
            },
            tx,
        );

        let config = ret.0.corenodes_config.clone();
        let data = ret.0.data.clone();

        task::spawn(
            async move {
                let request_handler =
                    TobRequestHandler::new(config, tob_stream, data);

                if let Err(_) = request_handler.serve().await {
                    error!("failed request handling");
                }
            }
            .instrument(trace_span!("tob_request_receiver")),
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
            info!("CLIENT connection {:?}", peer_pub);

            let module_cache = self.module_cache.clone();
            let bls_sk = self.bls_kp.sig_key.clone();

            task::spawn(
                async move {
                    let client_handler = ClientRequestHandler::new(
                        connection,
                        data,
                        module_cache,
                        bls_sk,
                    );

                    if let Err(_) = client_handler.serve().await {
                        error!("failed request handling");
                    }
                }
                .instrument(trace_span!("client_request_receiver")),
            );
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
    bls_sk: BlsSigKey,
}

impl ClientRequestHandler {
    fn new(
        connection: Connection,
        data: ProtectedTree,
        module_cache: ProtectedModuleCache,
        bls_sk: BlsSigKey,
    ) -> Self {
        Self {
            connection,
            data,
            module_cache,
            bls_sk,
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
        module_cache: &mut ModuleCache<RecordID>,
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
        rt: RuleTransaction,
    ) -> Result<ExecuteResult, CoreNodeError> {
        let misc_digest =
            super::get_misc_digest(rt.rule_version(), rt.rule_arguments());

        let used_record_count: usize = rt.proof().len();
        if used_record_count > RECORD_LIMIT {
            let cause = format!("Error processing transaction: record limit exceeded. Limit is {}, rule touches {}", RECORD_LIMIT, used_record_count);
            error!("{}", cause);
            return Ok(ExecuteResult::fail(
                rt.rule_id().clone(),
                rt.rule_version().clone(),
                misc_digest,
                cause,
            ));
        }

        let tree_guard = data.read().await;

        if !tree_guard
            .consistent_given_records(rt.proof(), rt.touched_records())
        {
            let cause =
                format!("Error processing transaction: invalid merkle proof");
            error!("{}", cause);
            return Ok(ExecuteResult::fail(
                rt.rule_id().clone(),
                rt.rule_version().clone(),
                misc_digest,
                cause,
            ));
        }

        let mut cache_guard = module_cache.write().await;
        let res = ClientRequestHandler::execute_transaction(
            rt.rule_id(),
            rt.rule_version(),
            rt.rule_arguments(),
            rt.proof(),
            &mut cache_guard,
            &tree_guard,
        );
        drop(cache_guard);
        drop(tree_guard);

        match res {
            Err(_) => {
                return Ok(ExecuteResult::fail(
                    rt.rule_id().clone(),
                    rt.rule_version().clone(),
                    misc_digest,
                    format!("failed executing transaction : error message WIP"),
                ))
            }
            Ok(mut output_ledger) => {
                let mut output: Vec<(RecordID, Touch)> = vec![];

                let mut input_ledger: Ledger = rt
                    .proof()
                    .clone_to_vec()
                    .into_iter()
                    .filter(|(k, _)| k != rt.rule_id())
                    .collect();

                for k in rt.touched_records().clone().drain(..) {
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
                    rt.rule_id().clone(),
                    rt.rule_version().clone(),
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
                        rt.rule_id()
                    );

                    let proof = rt.proof().clone();

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

                    let d = if let Ok(output) = result.output.clone() {
                        let p = PayloadForTob::new(
                            result.rule_record_id.clone(),
                            result.misc_digest.clone(),
                            proof,
                            output,
                        );
                        drop::crypto::hash(&p).unwrap()
                    } else {
                        drop::crypto::hash(&result).unwrap()
                    };

                    let bls_signature =
                        BlsSignature::new(d.as_ref(), &self.bls_sk);

                    self.connection
                        .send(&UserCoreResponse::Execute((
                            result,
                            bls_signature.into(),
                        )))
                        .await?;
                }
            }
        }

        self.connection.close().await?;

        info!("End of client connection");

        Ok(())
    }
}

struct TobRequestHandler<T> {
    config: SharedConfig,
    tob_stream: T,
    data: ProtectedTree,
}

impl<T> TobRequestHandler<T>
where
    T: Stream<Item = TobRequest> + Unpin,
{
    fn new(config: SharedConfig, tob_stream: T, data: ProtectedTree) -> Self {
        Self {
            config,
            tob_stream,
            data,
        }
    }

    fn validate_sigs(
        config: &SharedConfig,
        payload: &PayloadForTob,
        sig_info: &BlsSigInfo,
    ) -> bool {
        let mut nodes = config.get_group_covering(payload.rule_id());
        nodes.sort_by(|x, y| x.dir_info().public().cmp(&y.dir_info().public()));
        let ver_keys: Vec<&BlsVerKey> = nodes
            .drain(..)
            .enumerate()
            .filter(|(i, _)| sig_info.mask()[*i] == true)
            .map(|(_, k)| k.bls_public())
            .collect();
        let pk = BlsVerifySignatures::from_verkeys(ver_keys);

        let params = BlsParams::new("some publicly known string".as_bytes());
        let d = drop::crypto::hash(payload).unwrap();

        sig_info.sig().verify(d.as_ref(), &pk, &params)
    }

    async fn serve(mut self) -> Result<(), CoreNodeError> {
        while let Some(txr) = self.tob_stream.next().await {
            match txr {
                TobRequest::Apply((req, sig)) => {
                    if !Self::validate_sigs(&self.config, &req, &sig) {
                        let cause = format!(
                            "Error processing transaction: invalid signatures"
                        );
                        error!("{}", cause);
                        continue;
                    }

                    let touched_records =
                        req.output().iter().map(|x| x.0.clone()).collect();

                    let mut tree_guard = self.data.write().await;

                    if !tree_guard
                        .consistent_given_records(req.proof(), &touched_records)
                    {
                        let cause = format!("Error processing transaction: invalid merkle proof");
                        error!("{}", cause);
                        continue;
                    }

                    tree_guard.merge_consistent(req.proof(), &touched_records);

                    for (k, t) in req.output().iter() {
                        match t {
                            Touch::Modified(v) | Touch::Added(v) => {
                                tree_guard.insert(k.clone(), v.clone());
                            }
                            Touch::Deleted => {
                                tree_guard.remove(k);
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

        info!("End of TOB stream task");

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::super::{DataTree, UserCoreRequest, UserCoreResponse};
    use crate::utils::test::*;
    extern crate test;
    use super::*;
    // use test::Bencher;
    // use wasm_common_bindings::{ContextLedger, Ledger};

    use rand::thread_rng;

    use crate::single_server_tob::TobDeliverer;
    use tracing::trace_span;
    use tracing_futures::Instrument;

    #[tokio::test]
    async fn corenode_shutdown() {
        init_logger();

        let fake_tob_addr = next_test_ip4();
        let exchanger = Exchanger::random();
        let fake_tob_info =
            DirectoryInfo::from((*exchanger.keypair().public(), fake_tob_addr));

        let params = BlsParams::new("some publicly known string".as_bytes());
        let mut rng = thread_rng();
        let bls_kp = BlsKeypair::new(&mut rng, &params);

        let deliverer = TobDeliverer::new(
            next_test_ip4(),
            Exchanger::random(),
            fake_tob_info.public().clone(),
        )
        .await;
        let (exit_tx, handle, _) = setup_corenode(
            next_test_ip4(),
            CommKeyPair::random(),
            bls_kp,
            deliverer,
            SystemConfig::new(vec![]),
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
            RunningConfig::setup(get_balanced_prefixes(1), DataTree::new(), 10)
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

    #[tokio::test]
    async fn request_execute() {
        init_logger();

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
            RunningConfig::setup(get_balanced_prefixes(1), t.clone(), 10).await;

        let mut c_node = create_peer_and_connect(&config.corenodes[0].2).await;
        let mut c_tob = create_peer_and_connect(&config.tob_info).await;

        let local = c_node.local_addr().expect("getaddr failed");

        async move {
            let txr = UserCoreRequest::GetProof(vec![
                "Alice".to_string(),
                "Bob".to_string(),
            ]);
            c_node.send(&txr).await.expect("send failed");

            let resp = c_node
                .receive::<UserCoreResponse>()
                .await
                .expect("recv failed");

            let proof = match resp {
                UserCoreResponse::GetProof((_, p)) => p,
                _ => unreachable!(),
            };

            let args = ("Alice".to_string(), "Bob".to_string(), 50i32);
            let rt = RuleTransaction::new(
                proof,
                rule_record_id,
                rule_digest,
                vec!["Alice".to_string(), "Bob".to_string()],
                &args,
            );

            let txr: &UserCoreRequest = &UserCoreRequest::Execute(rt);
            c_node.send(&txr).await.expect("send failed");
            let resp = c_node
                .receive::<UserCoreResponse>()
                .await
                .expect("recv failed");

            let (_res, _bls_sig) = match resp {
                UserCoreResponse::Execute(x) => x,
                _ => panic!("wrong response from corenode"),
            };

            // TODO: assert result and verify signature;

            // assert_eq!(
            //     resp,
            //     UserCoreResponse::Execute((res, bls_sig)),
            //     "wrong response from corenode"
            // );

            let _ = c_tob.close().await;
            let _ = c_node.close().await;
        }
        .instrument(trace_span!("request_add", client = %local))
        .await;

        config.tear_down().await;
    }
}
