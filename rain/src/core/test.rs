use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};

use super::{CoreNode, DataTree, RuleTransaction, TobServer};

use drop::crypto::key::exchange::Exchanger;
use drop::net::{
    Connection, Connector, DirectoryInfo, DirectoryServer, TcpConnector,
    TcpListener,
};

use tokio::sync::oneshot::Sender;
use tokio::task::{self, JoinHandle};

use tracing::trace_span;
use tracing_futures::Instrument;
use tracing_subscriber::FmtSubscriber;

use futures::future;

static PORT_OFFSET: AtomicU16 = AtomicU16::new(0);

/// Initialize an asynchronous logger for test environment
pub fn init_logger() {
    if let Some(level) = env::var("RUST_LOG").ok().map(|x| x.parse().ok()) {
        let subscriber =
            FmtSubscriber::builder().with_max_level(level).finish();

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
    RuleTransaction::new(DataTree::new(), "Alice".to_string(), &(123))
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
    pub async fn setup(nr_peer: usize, dt: DataTree) -> Self {
        if nr_peer == 0 {
            panic!("SetupConfig must be setup with at least 1 core node");
        }

        let (dir_exit, dir_handle, dir_info) = setup_dir(next_test_ip4()).await;

        let tob_addr = next_test_ip4();

        let corenodes = future::join_all((0..nr_peer).map(|_| {
            setup_corenode(
                next_test_ip4(),
                dir_info.addr(),
                tob_addr,
                dt.clone(),
            )
        }))
        .await;

        // must setup tob AFTER corenodes (tob waits for corenodes to join directory)
        let (tob_exit, tob_handle, tob_info) =
            setup_tob(tob_addr, &dir_info, nr_peer).await;

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

pub async fn setup_corenode(
    server_addr: SocketAddr,
    dir_addr: SocketAddr,
    tob_addr: SocketAddr,
    dt: DataTree,
) -> (Sender<()>, JoinHandle<()>, DirectoryInfo) {
    let (core_server, exit_tx) =
        CoreNode::new(server_addr, dir_addr, tob_addr, dt)
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

    let dir_info = DirectoryInfo::from((dir_public, dir_addr));
    (exit_dir, handle_dir, dir_info)
}

pub async fn setup_tob(
    tob_addr: SocketAddr,
    dir_info: &DirectoryInfo,
    nr_peer: usize,
) -> (Sender<()>, JoinHandle<()>, DirectoryInfo) {
    let (tob_server, exit_tx) = TobServer::new(tob_addr, dir_info, nr_peer)
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

#[tokio::test]
async fn config_setup_teardown() {
    init_logger();

    let config = SetupConfig::setup(5, DataTree::new()).await;
    config.tear_down().await;
}

// async fn create_peer_and_connect_via_directory(
//     target: &PublicKey,
//     dir_info: &DirectoryInfo,
// ) -> Connection {
//     let exchanger = Exchanger::random();
//     let connector = TcpConnector::new(exchanger);
//     let mut dir_connector = DirectoryConnector::new(connector);

//     dir_connector
//         .wait(1, dir_info)
//         .await
//         .expect("could not wait");

//     let connection = dir_connector
//         .connect(target, dir_info)
//         .instrument(trace_span!("adder"))
//         .await
//         .expect("connect failed");

//     connection
// }
