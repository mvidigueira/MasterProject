use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use crate::corenode::{
    BlsKeypair, BlsParams, BlsSigInfo, BlsSigKey, BlsSignature, CoreNode,
    CoreNodeInfo, DataTree, PayloadForTob, Prefix, RuleTransaction,
    SystemConfig,
};
use rand::{prelude::SliceRandom, thread_rng};

use crate::single_server_tob::TobDeliverer;
use crate::single_server_tob::TobServer;

use drop::crypto::key::exchange::{
    Exchanger, KeyPair as CommKeyPair, PublicKey as CommPubKey,
};
use drop::net::{Connection, Connector, DirectoryInfo, TcpConnector};

use tokio::sync::oneshot::Sender;
use tokio::task::{self, JoinHandle};

use tracing::trace_span;
use tracing_futures::Instrument;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use futures::future;

static PORT_OFFSET: AtomicU16 = AtomicU16::new(0);

/// Initialize an asynchronous logger for test environment
pub fn init_logger() {
    if let Ok(filter) = EnvFilter::try_from_default_env() {
        let subscriber =
            FmtSubscriber::builder().with_env_filter(filter).finish();

        let _ = tracing::subscriber::set_global_default(subscriber);
    }
}

pub fn next_test_ip4() -> SocketAddr {
    (
        Ipv4Addr::LOCALHOST,
        9000 + PORT_OFFSET.fetch_add(1, Ordering::AcqRel),
    )
        .into()
}

pub fn get_example_rt() -> RuleTransaction {
    RuleTransaction::new(
        DataTree::new(),
        "Alice".to_string(),
        drop::crypto::hash(&"transaction record bytes".to_string()).unwrap(),
        vec!["Alice".to_string()],
        &(123),
    )
}

pub fn get_example_tobpayload() -> PayloadForTob {
    PayloadForTob::new(
        "some rule".to_string(),
        drop::crypto::hash(&"version + args").unwrap(),
        DataTree::new(),
        vec![],
    )
}

pub fn get_example_bls_sig_info() -> BlsSigInfo {
    let sig = BlsSignature::new(&vec![], &BlsSigKey::new(&mut thread_rng()));
    BlsSigInfo::new(sig, vec![])
}

pub struct RunningConfig {
    pub tob_info: DirectoryInfo,
    pub tob_exit: Sender<()>,
    pub tob_handle: JoinHandle<()>,

    pub corenodes: Vec<(Sender<()>, JoinHandle<()>, DirectoryInfo)>,
    pub corenodes_config: SystemConfig<Arc<CoreNodeInfo>>,
}

impl RunningConfig {
    pub async fn setup_asymetric<I: Into<Prefix>>(
        mut prefix_info: Vec<Vec<I>>,
        nr_peer_tob: usize,
        dt: DataTree,
        h_len: usize,
    ) -> Self {
        let nr_peer = prefix_info.len();

        if nr_peer == 0 {
            panic!("RunningConfig must be set up with at least 1 core node");
        }

        let prefix_info: Vec<Vec<Prefix>> = prefix_info
            .drain(..)
            .map(|mut p_list| p_list.drain(..).map(|i| i.into()).collect())
            .collect();

        let mut corenodes_config = vec![];
        for p in prefix_info {
            let mut cn = CoreNodeConfig::random();
            cn.set_prefix_list(p);
            corenodes_config.push(cn);
        }
        let tob_nodes_config = vec![CoreNodeConfig::random()];

        let (tob_exit, tob_handle, mut tob_deliverers) =
            setup_single_server_tob(
                &corenodes_config,
                &tob_nodes_config,
                nr_peer_tob,
            )
            .await;

        let comb = corenodes_config
            .iter()
            .map(|v| {
                let i = CoreNodeInfo::new(
                    DirectoryInfo::from((
                        v.comm_kp().public().clone(),
                        v.user_addr(),
                    )),
                    v.bls_kp().ver_key.clone(),
                );
                let p = v.prefix_list().clone();
                (Arc::new(i), p)
            })
            .collect();

        let system_config = SystemConfig::from_inverse(comb);

        let corenodes = future::join_all(corenodes_config.iter().map(|node| {
            setup_corenode(
                node.user_addr(),
                node.comm_kp().clone(),
                BlsKeypair {
                    sig_key: node.bls_kp().sig_key.clone(),
                    ver_key: node.bls_kp().ver_key.clone(),
                },
                tob_deliverers.remove(0),
                system_config.clone(),
                dt.clone(),
                h_len,
                node.prefix_list().clone(),
            )
        }))
        .await;

        let tob_info = DirectoryInfo::from((
            *tob_nodes_config[0].comm_kp().public(),
            tob_nodes_config[0].user_addr(),
        ));

        Self {
            tob_info: tob_info,
            tob_exit: tob_exit,
            tob_handle: tob_handle,

            corenodes: corenodes,
            corenodes_config: system_config,
        }
    }

    pub async fn setup<I: Into<Prefix>>(
        prefix_info: Vec<Vec<I>>,
        dt: DataTree,
        h_len: usize,
    ) -> Self {
        let i = prefix_info.len();
        Self::setup_asymetric(prefix_info, i, dt, h_len).await
    }

    pub async fn tear_down(self) {
        for (exit, handle, _) in self.corenodes {
            wait_for_server(exit, handle).await;
        }
        wait_for_server(self.tob_exit, self.tob_handle).await;
    }
}

pub struct CoreNodeConfig {
    user_addr: SocketAddr,
    tob_addr: SocketAddr,
    comm_kp: CommKeyPair,
    bls_kp: BlsKeypair,
    prefix_list: Vec<Prefix>,
}

impl CoreNodeConfig {
    pub fn new(
        user_addr: SocketAddr,
        tob_addr: SocketAddr,
        comm_kp: CommKeyPair,
        bls_kp: BlsKeypair,
        prefix_list: Vec<Prefix>,
    ) -> Self {
        Self {
            user_addr,
            tob_addr,
            comm_kp,
            bls_kp,
            prefix_list,
        }
    }

    pub fn random() -> Self {
        let params = BlsParams::new("some publicly known string".as_bytes());
        let mut rng = thread_rng();
        let bls_kp = BlsKeypair::new(&mut rng, &params);

        Self {
            user_addr: next_test_ip4(),
            tob_addr: next_test_ip4(),
            comm_kp: CommKeyPair::random(),
            bls_kp: bls_kp,
            prefix_list: vec![],
        }
    }

    pub fn user_addr(&self) -> SocketAddr {
        self.user_addr
    }

    pub fn tob_addr(&self) -> SocketAddr {
        self.tob_addr
    }

    pub fn comm_kp(&self) -> &CommKeyPair {
        &self.comm_kp
    }

    pub fn bls_kp(&self) -> &BlsKeypair {
        &self.bls_kp
    }

    pub fn prefix_list(&self) -> &Vec<Prefix> {
        &self.prefix_list
    }

    pub fn set_prefix_list(&mut self, v: Vec<Prefix>) {
        self.prefix_list = v;
    }
}

impl TobNodeConfig for CoreNodeConfig {
    fn user_addr(&self) -> SocketAddr {
        self.user_addr()
    }
    fn tob_addr(&self) -> SocketAddr {
        self.tob_addr()
    }
    fn comm_kp(&self) -> &CommKeyPair {
        self.comm_kp()
    }
}

pub trait TobNodeConfig {
    fn user_addr(&self) -> SocketAddr;
    fn tob_addr(&self) -> SocketAddr;
    fn comm_kp(&self) -> &CommKeyPair;
}

pub async fn setup_corenode<I: Into<Prefix>>(
    server_addr: SocketAddr,
    comm_kp: CommKeyPair,
    bls_kp: BlsKeypair,
    tob_deliverer: TobDeliverer,
    corenodes_info: SystemConfig<Arc<CoreNodeInfo>>,
    dt: DataTree,
    h_len: usize,
    mut prefix_list: Vec<I>,
) -> (Sender<()>, JoinHandle<()>, DirectoryInfo) {
    let (core_server, exit_tx) = CoreNode::new(
        server_addr,
        comm_kp,
        bls_kp,
        tob_deliverer,
        corenodes_info,
        dt,
        h_len,
        prefix_list.drain(..).map(|x| x.into()).collect(),
    )
    .await
    .expect("core node creation failed");

    let info: DirectoryInfo =
        (core_server.public_key().clone(), server_addr).into();

    let handle =
        task::spawn(
            async move {
                core_server.serve().await.expect("corenode serve failed")
            }
            .instrument(trace_span!("corenode_serve")),
        );

    (exit_tx, handle, info)
}

pub async fn setup_single_server_tob_deliverers<T: TobNodeConfig>(
    observers: &Vec<T>,
    tob_info: DirectoryInfo,
) -> Vec<TobDeliverer> {
    let mut v = vec![];
    for observer in observers.iter() {
        let deliverer = TobDeliverer::new(
            Exchanger::new(observer.comm_kp().clone()),
            tob_info,
        )
        .await;
        v.push(deliverer);
    }
    v
}

// tob_recipients == observer_nodes.len() unless an asymetric test
// is being conducted (where tob_nodes only send messages to
// 'tob_recipients' number of observers)
pub async fn setup_single_server_tob<T: TobNodeConfig>(
    observer_nodes: &Vec<T>,
    tob_nodes: &Vec<T>,
    tob_recipients: usize,
) -> (Sender<()>, JoinHandle<()>, Vec<TobDeliverer>) {
    assert_eq!(tob_nodes.len(), 1);

    let tob_config = &tob_nodes[0];
    let (tob_addr, tob_pub) =
        (tob_config.tob_addr(), *tob_config.comm_kp().public());

    let tob_info = DirectoryInfo::from((tob_pub, tob_addr));

    let v = setup_single_server_tob_deliverers(observer_nodes, tob_info).await;

    let c: Vec<CommPubKey> = observer_nodes
        .iter()
        .map(|x| {
            x.comm_kp().public().clone()
        })
        .collect();

    let (tob_server, exit_tx) = TobServer::new(
        tob_config.user_addr(),
        tob_config.tob_addr(),
        Exchanger::new(tob_config.comm_kp().clone()),
        c[0..tob_recipients].to_vec(),
    )
    .await
    .expect("tob server creation failed");

    let handle = task::spawn(
        async move { tob_server.serve().await.expect("tob serve failed") }
            .instrument(trace_span!("tob_serve")),
    );

    (exit_tx, handle, v)
}

pub async fn setup_tob(
    user_addr: SocketAddr,
    tob_addr: SocketAddr,
    exchanger: Exchanger,
    observers: Vec<CommPubKey>,
) -> (Sender<()>, JoinHandle<()>, DirectoryInfo) {
    let tob_info: DirectoryInfo = (exchanger.keypair().public().clone(), user_addr).into();

    let (tob_server, exit_tx) =
        TobServer::new(user_addr, tob_addr, exchanger, observers)
            .await
            .expect("tob server creation failed");

    let handle = task::spawn(
        async move { tob_server.serve().await.expect("tob serve failed") }
            .instrument(trace_span!("tob_serve")),
    );

    (exit_tx, handle, tob_info)
}

pub async fn wait_for_server<T>(exit_tx: Sender<()>, handle: JoinHandle<T>) {
    exit_tx.send(()).expect("exit_failed");
    handle.await.expect("server failed");
}

pub async fn create_peer_and_connect(target: &DirectoryInfo) -> Connection {
    let exchanger = Exchanger::random();
    let connector = TcpConnector::new(exchanger);

    let connection = connector
        .connect(target.public(), &target.addr())
        .instrument(trace_span!("adder"))
        .await
        .expect("connect failed");

    connection
}

pub fn get_balanced_prefixes(n: usize) -> Vec<Vec<Prefix>> {
    let log2 =
        (std::mem::size_of::<usize>() * 8) as u32 - n.leading_zeros() - 1;
    let pow2 = (2 as usize).pow(log2);
    let r = n - pow2;
    let z = n - 2 * r;

    let mut list: Vec<Vec<Prefix>> = vec![];
    let mut base = Prefix::new(vec![0], 0);
    base.set_length_in_bits(log2 as usize);
    for _ in 0..z {
        list.push(vec![base.clone()]);
        base.increment();
    }
    base.set_length_in_bits(log2 as usize + 1);
    for _ in 0..2 * r {
        list.push(vec![base.clone()]);
        base.increment();
    }

    list
}

// This function creates n/coverage groups each covering a different set of prefixes.
// Each group is assigned at least 'coverage' different nodes at random, making it so
// every prefix (in every group) is covered by at least 'coverage' different nodes.
// This distribution can tolerate '(coverage - 1) / 2' byzantine failures (optimal).
// The 'granularity' affects the number of prefixes assigned to each shard. Higher
// granularity tends to decrease the difference in relative size of each shard (more balanced).
// (Recommendation: granularity >= n)
pub fn get_prefixes_bft(
    n: usize,
    coverage: usize,
    granularity: usize,
) -> Vec<Vec<Prefix>> {
    if n < coverage {
        panic!("number of nodes must be greater or equal to coverage");
    }

    let mut prefixes: Vec<Prefix> = get_balanced_prefixes(granularity)
        .drain(..)
        .map(|mut x| x.pop().unwrap())
        .collect();
    let mut rng = rand::thread_rng();
    prefixes.shuffle(&mut rng);

    let num_groups = n / coverage;

    let mut temp_list: Vec<Vec<Prefix>> = vec![vec!(); num_groups];
    let mut final_list: Vec<Vec<Prefix>> = vec![];

    let mut i = 0;
    for p in prefixes {
        temp_list[i].push(p);
        i = (i + 1) % num_groups;
    }

    let remainder = n % coverage;
    for i in 0..remainder {
        final_list.push(temp_list[i].clone());
    }
    for l in temp_list {
        for _ in 0..coverage {
            final_list.push(l.clone());
        }
    }

    final_list.shuffle(&mut rng);

    final_list
}

#[tokio::test]
async fn config_setup_teardown() {
    init_logger();

    let config = RunningConfig::setup(
        vec![vec!["0"], vec!["0"], vec!["0"], vec!["0"], vec!["0"]],
        DataTree::new(),
        1,
    )
    .await;
    config.tear_down().await;
}
