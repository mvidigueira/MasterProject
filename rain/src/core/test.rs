use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};

use super::{CoreNode, DataTree, RuleTransaction, TobServer, Prefix};

use drop::crypto::key::exchange::Exchanger;
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
        vec!["Alice".to_string()],
        &(123),
    )
}

pub struct SetupConfig {
    pub dir_info: DirectoryInfo,
    pub dir_exit: Sender<()>,
    pub dir_handle: JoinHandle<()>,

    pub tob_info: DirectoryInfo,
    pub tob_exit: Sender<()>,
    pub tob_handle: JoinHandle<()>,

    pub corenodes: Vec<(Sender<()>, JoinHandle<()>, DirectoryInfo)>,
}

impl SetupConfig {
    pub async fn setup<I: Into<Prefix>>(mut prefix_lists: Vec<Vec<I>>, dt: DataTree, h_len: usize) -> Self {
        let nr_peer = prefix_lists.len();

        if nr_peer == 0 {
            panic!("SetupConfig must be setup with at least 1 core node");
        }

        let (dir_exit, dir_handle, dir_info) = setup_dir(next_test_ip4()).await;

        let tob_addr = next_test_ip4();

        let tob_exchanger = Exchanger::random();
        let tob_info = DirectoryInfo::from((*tob_exchanger.keypair().public(), tob_addr));

        let corenodes = future::join_all(prefix_lists.drain(..).map(|p_list| {
            setup_corenode(
                next_test_ip4(),
                &dir_info,
                &tob_info,
                dt.clone(),
                h_len,
                p_list,
            )
        }))
        .await;

        // must setup tob AFTER corenodes (tob waits for corenodes to join directory)
        let (tob_exit, tob_handle, tob_info) =
            setup_tob(tob_addr, tob_exchanger, &dir_info, nr_peer).await;

        Self {
            dir_info,
            dir_exit,
            dir_handle,

            tob_info,
            tob_exit,
            tob_handle,

            corenodes,
        }
    }

    pub async fn setup_asymetric<I: Into<Prefix>>(mut prefix_lists: Vec<Vec<I>>, nr_peer_tob: usize, dt: DataTree, h_len: usize) -> Self {
        let nr_peer_nodes = prefix_lists.len();
        
        if nr_peer_nodes == 0 {
            panic!("SetupConfig must be setup with at least 1 core node");
        }

        let (dir_exit, dir_handle, dir_info) = setup_dir(next_test_ip4()).await;

        let tob_addr = next_test_ip4();

        let tob_exchanger = Exchanger::random();
        let tob_info = DirectoryInfo::from((*tob_exchanger.keypair().public(), tob_addr));

        let corenodes = future::join_all(prefix_lists.drain(..).map(|p_list| {
            setup_corenode(
                next_test_ip4(),
                &dir_info,
                &tob_info,
                dt.clone(),
                h_len,
                p_list,
            )
        }))
        .await;

        // must setup tob AFTER corenodes (tob waits for corenodes to join directory)
        let (tob_exit, tob_handle, tob_info) =
            setup_tob(tob_addr, tob_exchanger, &dir_info, nr_peer_tob).await;

        Self {
            dir_info,
            dir_exit,
            dir_handle,

            tob_info,
            tob_exit,
            tob_handle,

            corenodes,
        }
    }

    pub async fn tear_down(self) {
        for (exit, handle, _) in self.corenodes {
            wait_for_server(exit, handle).await;
        }
        wait_for_server(self.tob_exit, self.tob_handle).await;
        wait_for_server(self.dir_exit, self.dir_handle).await;
    }
}

pub async fn setup_corenode<I: Into<Prefix>>(
    server_addr: SocketAddr,
    dir_info: &DirectoryInfo,
    tob_info: &DirectoryInfo,
    dt: DataTree,
    h_len: usize,
    mut prefix_list: Vec<I>,
) -> (Sender<()>, JoinHandle<()>, DirectoryInfo) {
    let (core_server, exit_tx) =
        CoreNode::new(server_addr, dir_info, tob_info, dt, h_len, 
            prefix_list.drain(..).map(|x| x.into()).collect())
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
    dir_info: &DirectoryInfo,
    nr_peer: usize,
) -> (Sender<()>, JoinHandle<()>, DirectoryInfo) {
    let (tob_server, exit_tx) = TobServer::new(tob_addr, exchanger, dir_info, nr_peer)
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
    let log2 = (std::mem::size_of::<usize>() * 8) as u32 - n.leading_zeros() - 1;
    let pow2 =  (2 as usize).pow(log2);
    let r = n - pow2;
    let z = n - 2*r;

    let mut list: Vec<Vec<Prefix>> = vec!();
    let mut base = Prefix::new(vec!(0), 0);
    base.set_length_in_bits(log2 as usize);
    for _ in 0..z {
        list.push(vec!(base.clone()));
        base.increment();
    }
    base.set_length_in_bits(log2 as usize + 1);
    for _ in 0..2*r {
        list.push(vec!(base.clone()));
        base.increment();
    }

    list
}

#[tokio::test]
async fn config_setup_teardown() {
    init_logger();

    let config = SetupConfig::setup(vec!(vec!("0"), vec!("0"), vec!("0"), vec!("0"), vec!("0")), DataTree::new(), 1).await;
    config.tear_down().await;
}
