use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use super::{BlsSignature, BlsSigKey, BlsSigInfo, BlsKeypair, BlsParams};
use rand::thread_rng;

use super::{
    CoreNode, CoreNodeInfo, DataTree, PayloadForTob, Prefix, RuleTransaction, SystemConfig
};

use crate::tob::TobServer;

use drop::crypto::key::exchange::{Exchanger, KeyPair as CommKeyPair};
use drop::net::{
    Connection, Connector, DirectoryInfo, DirectoryServer, TcpConnector,
    TcpListener,
};

use tokio::sync::oneshot::Sender;
use tokio::task::{self, JoinHandle};

use tracing::trace_span;
use tracing_futures::Instrument;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use futures::future;

use rand::prelude::SliceRandom;

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
    let sig = BlsSignature::new(&vec!(), &BlsSigKey::new(&mut thread_rng()));
    BlsSigInfo::new(sig, vec!())
}

pub struct SetupConfig {
    pub tob_info: DirectoryInfo,
    pub tob_exit: Sender<()>,
    pub tob_handle: JoinHandle<()>,

    pub corenodes: Vec<(Sender<()>, JoinHandle<()>, DirectoryInfo)>,
    pub corenodes_config: SystemConfig<Arc<CoreNodeInfo>>,
}

impl SetupConfig {
    pub async fn setup<I: Into<Prefix>>(
        mut prefix_info: Vec<Vec<I>>,
        dt: DataTree,
        h_len: usize,
    ) -> Self {
        let nr_peer = prefix_info.len();

        if nr_peer == 0 {
            panic!("SetupConfig must be set up with at least 1 core node");
        }

        let tob_addr = next_test_ip4();
        let tob_exchanger = Exchanger::random();
        let tob_info =
            DirectoryInfo::from((*tob_exchanger.keypair().public(), tob_addr));

        let prefix_info: Vec<Vec<Prefix>> = prefix_info.drain(..).map(
            |mut p_list| p_list.drain(..).map(|i| i.into()).collect()
        ).collect();

        let mut corenodes_info = vec!();
        let mut kps = vec!();
        for _ in 0..nr_peer {
            let comm_kp = CommKeyPair::random();
            let address = next_test_ip4();
            let params = BlsParams::new("some publicly known string".as_bytes());
            let mut rng = thread_rng();
            let bls_kp = BlsKeypair::new(&mut rng, &params);

            let info = DirectoryInfo::from((comm_kp.public().clone(), address.clone()));
            let info = CoreNodeInfo::new(info, bls_kp.ver_key.clone());
            corenodes_info.push(info);

            kps.push((address, comm_kp, bls_kp));
        }

        let comb = corenodes_info.iter().map(|v| Arc::new(v.clone())).zip(prefix_info.iter().map(|p| p.clone())).collect();
        let corenodes_config = SystemConfig::from_inverse(comb);

        let corenodes = future::join_all(
            kps.drain(..).enumerate().map(
                |(i, (a,b,c))| {
                    setup_corenode(a, b, c, &tob_info, corenodes_config.clone(), dt.clone(), h_len, prefix_info[i].clone())
                }
            )
        ).await;

        // must setup tob AFTER corenodes (tob waits for corenodes to join directory)
        let (tob_exit, tob_handle, tob_info) =
            setup_tob(tob_addr, tob_exchanger, corenodes_info.iter().map(|x| x.dir_info().clone()).collect()).await;

        Self {
            tob_info,
            tob_exit,
            tob_handle,

            corenodes,
            corenodes_config,
        }
    }

    pub async fn setup_asymetric<I: Into<Prefix>>(
        mut prefix_info: Vec<Vec<I>>,
        nr_peer_tob: usize,
        dt: DataTree,
        h_len: usize,
    ) -> Self {
        let nr_peer = prefix_info.len();

        if nr_peer == 0 {
            panic!("SetupConfig must be set up with at least 1 core node");
        }

        let tob_addr = next_test_ip4();
        let tob_exchanger = Exchanger::random();
        let tob_info =
            DirectoryInfo::from((*tob_exchanger.keypair().public(), tob_addr));

        let prefix_info: Vec<Vec<Prefix>> = prefix_info.drain(..).map(
            |mut p_list| p_list.drain(..).map(|i| i.into()).collect()
        ).collect();

        let mut corenodes_info = vec!();
        let mut kps = vec!();
        for _ in 0..nr_peer {
            let comm_kp = CommKeyPair::random();
            let address = next_test_ip4();
            let params = BlsParams::new("some publicly known string".as_bytes());
            let mut rng = thread_rng();
            let bls_kp = BlsKeypair::new(&mut rng, &params);

            let info = DirectoryInfo::from((comm_kp.public().clone(), address.clone()));
            let info = CoreNodeInfo::new(info, bls_kp.ver_key.clone());
            corenodes_info.push(info);

            kps.push((address, comm_kp, bls_kp));
        }

        let comb = corenodes_info.iter().map(|v| Arc::new(v.clone())).zip(prefix_info.iter().map(|p| p.clone())).collect();
        let corenodes_config = SystemConfig::from_inverse(comb);

        let corenodes = future::join_all(
            kps.drain(..).enumerate().map(
                |(i, (a,b,c))| {
                    setup_corenode(a, b, c, &tob_info, corenodes_config.clone(), dt.clone(), h_len, prefix_info[i].clone())
                }
            )
        ).await;

        let corenodes_info = corenodes
            .iter()
            .map(|x| x.2)
            .collect::<Vec<DirectoryInfo>>()[0..nr_peer_tob]
            .to_vec();

        // must setup tob AFTER corenodes (tob waits for corenodes to join directory)
        let (tob_exit, tob_handle, tob_info) =
            setup_tob(tob_addr, tob_exchanger, corenodes_info).await;

        Self {
            tob_info,
            tob_exit,
            tob_handle,

            corenodes,
            corenodes_config,
        }
    }

    pub async fn tear_down(self) {
        for (exit, handle, _) in self.corenodes {
            wait_for_server(exit, handle).await;
        }
        wait_for_server(self.tob_exit, self.tob_handle).await;
    }
}

pub async fn setup_corenode<I: Into<Prefix>>(
    server_addr: SocketAddr,
    comm_kp: CommKeyPair,
    bls_kp: BlsKeypair,
    tob_info: &DirectoryInfo,
    corenodes_info: SystemConfig<Arc<CoreNodeInfo>>,
    dt: DataTree,
    h_len: usize,
    mut prefix_list: Vec<I>
) -> (Sender<()>, JoinHandle<()>, DirectoryInfo) {
    let (core_server, exit_tx) = CoreNode::new(
        server_addr,
        comm_kp,
        bls_kp,
        tob_info,
        corenodes_info,
        dt,
        h_len,
        prefix_list.drain(..).map(|x| x.into()).collect()
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

pub async fn setup_dir(
    dir_addr: SocketAddr,
) -> (Sender<()>, JoinHandle<()>, DirectoryInfo) {
    let exchanger = Exchanger::random();
    let dir_public = exchanger.keypair().public().clone();
    let tcp = TcpListener::new(dir_addr, exchanger)
        .await
        .expect("bind failed");
    let (dir, exit_dir) = DirectoryServer::new(tcp);
    let handle_dir = task::spawn(
        async move { dir.serve().await.expect("dir serve failed") }
            .instrument(trace_span!("dir_serve")),
    );

    let dir_info = (dir_public, dir_addr).into();
    (exit_dir, handle_dir, dir_info)
}

pub async fn setup_tob(
    tob_addr: SocketAddr,
    exchanger: Exchanger,
    corenodes_info: Vec<DirectoryInfo>,
) -> (Sender<()>, JoinHandle<()>, DirectoryInfo) {
    let (tob_server, exit_tx) =
        TobServer::new(tob_addr, exchanger, corenodes_info)
            .await
            .expect("tob server creation failed");

    let info: DirectoryInfo =
        (tob_server.public_key().clone(), tob_addr).into();

    let handle = task::spawn(
        async move { tob_server.serve().await.expect("tob serve failed") }
            .instrument(trace_span!("tob_serve")),
    );

    (exit_tx, handle, info)
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

    let config = SetupConfig::setup(
        vec![vec!["0"], vec!["0"], vec!["0"], vec!["0"], vec!["0"]],
        DataTree::new(),
        1,
    )
    .await;
    config.tear_down().await;
}
