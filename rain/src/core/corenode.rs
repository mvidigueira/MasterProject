use std::fmt::Display;
use std::net::SocketAddr;
use std::sync::Arc;

use drop::crypto::key::exchange::{Exchanger, PublicKey};
use drop::net::{Connection, DirectoryListener, Listener,
    TcpConnector, TcpListener,
};

use super::{TxRequest, TxResponse, RecordID, RecordVal};
use merkle::Tree;

use super::CoreNodeError;

use std::time::Duration;
use tokio::net::ToSocketAddrs;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::time::timeout;
use tokio::task;
use tokio::sync::RwLock;

use tracing::{error, info, trace_span};
use tracing_futures::Instrument;

use drop::crypto::sign::Signer;

type DataTree = Tree<RecordID, RecordVal>;
type ProtectedTree = Arc<RwLock<DataTree>>;


struct CoreNode {
    dir_listener: DirectoryListener,
    tob_addr: SocketAddr,
    exit: Receiver<()>,

    data: ProtectedTree,

    // signer: Signer,
}

impl CoreNode {
    async fn new<A: ToSocketAddrs + Display>(
        node_addr: SocketAddr,
        dir_addr: A,
        tob_addr: SocketAddr,
    ) -> Result<(Self, Sender<()>), CoreNodeError> {
        let (tx, rx) = channel();

        let exchanger = Exchanger::random();

        let listener = TcpListener::new(node_addr, exchanger.clone())
            .await
            .expect("listen failed");

        let connector = TcpConnector::new(exchanger);

        let dir_listener =
            DirectoryListener::new(listener, connector, dir_addr).await?;

        let ret = (
            Self {
                dir_listener: dir_listener,
                tob_addr: tob_addr,
                exit: rx,
                
                data: Arc::from(RwLock::new(DataTree::new())),
            },
            tx,
        );

        Ok(ret)
    }

    // handle this better, don't use an all encompassing error
    async fn serve(mut self) -> Result<(), CoreNodeError> {
        let to = Duration::from_secs(1);

        loop {
            if self.exit.try_recv().is_ok() {
                info!("stopping core node");
                break;
            }

            let mut connection =
                match timeout(to, self.dir_listener.accept()).await {
                    Ok(Ok(socket)) => socket,
                    Ok(Err(e)) => {
                        error!("failed to accept directory connection: {}", e);
                        return Err(e.into());
                    }
                    Err(_) => continue,
                };

            let peer_addr = connection.peer_addr()?;
            
            let data = self.data.clone();

            if peer_addr == self.tob_addr {
                info!("new directory connection from TOB server: {}", peer_addr);                
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

        Ok(())
    }

    fn public_key(&self) -> &PublicKey {
        self.dir_listener.exchanger().keypair().public()
    }
}

struct TxRequestHandler {
    connection: Connection,
    data: ProtectedTree,
    from_client: bool,
}

impl TxRequestHandler {
    fn new(connection: Connection, data: ProtectedTree, from_client: bool) -> Self {
        Self {connection, data, from_client}
    }

    async fn handle_get_proof(&mut self, records: Vec<RecordID>) -> Result<(), CoreNodeError> {
        let guard = self.data.read().await;

        let mut t = guard.get_validator();
        for r in records {
            match guard.get_proof(&r) {
                Ok(proof) => {
                    t.merge(&proof).unwrap();
                }
                Err(_) => (),
            }
        }

        drop(guard);

        self.connection.send(&TxResponse::GetProof(t)).await?;

        Ok(())
    }

    async fn handle_execute(&mut self) -> Result<(), CoreNodeError> {
        info!("Execute success!");

        Ok(())
    }

    async fn serve(mut self) -> Result<(), CoreNodeError> {
        while let Ok(txr) = self.connection.receive::<TxRequest>().await {
            info!("Received request {:?}", txr);

            match txr {
                TxRequest::GetProof(records) => {
                    if self.from_client {
                        self.handle_get_proof(records).await?;
                    } else {
                        error!("TxRequest::GetProof should be sent directly by a client, not via TOB!");
                    }
                }
                TxRequest::Execute() => {
                    if self.from_client {
                        error!("Client attempting to execute directly. TxExecute can only come from TOB!");
                    } else {
                        self.handle_execute().await?;
                    }
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
    use super::*;
    use super::super::TobServer;

    use drop::net::connector::Connector;

    use drop::crypto::key::exchange::Exchanger;
    use drop::net::{
        Connection, DirectoryInfo, DirectoryServer,
        TcpConnector, TcpListener,
    };

    use tokio::task::{self, JoinHandle};

    use tracing::trace_span;
    use tracing_futures::Instrument;

    use futures::future;

    use crate::test::*;

    struct SetupConfig {
        dir_info: DirectoryInfo,
        dir_exit: Sender<()>,
        dir_handle: JoinHandle<()>,

        tob_info: DirectoryInfo,
        tob_exit: Sender<()>,
        tob_handle: JoinHandle<()>,

        corenodes: Vec<(Sender<()>, JoinHandle<()>, DirectoryInfo)>,
    }

    impl SetupConfig {
        async fn setup(nr_peer: usize) -> Self {
            let (dir_exit, dir_handle, dir_info) =
                setup_dir(next_test_ip4()).await;

            let tob_addr = next_test_ip4();

            let corenodes = future::join_all((0..nr_peer).map(|_| {
                setup_node(next_test_ip4(), dir_info.addr(), tob_addr)
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

        async fn tear_down(self) {
            for (exit, handle, _) in self.corenodes {
                wait_for_server(exit, handle).await;
            }
            wait_for_server(self.tob_exit, self.tob_handle).await;
            wait_for_server(self.dir_exit, self.dir_handle).await;
        }
    }

    async fn setup_node(
        server_addr: SocketAddr,
        dir_addr: SocketAddr,
        tob_addr: SocketAddr,
    ) -> (Sender<()>, JoinHandle<()>, DirectoryInfo) {
        let (core_server, exit_tx) =
            CoreNode::new(server_addr, dir_addr, tob_addr)
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

    async fn setup_dir(
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

    async fn setup_tob(
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

    async fn wait_for_server<T>(exit_tx: Sender<()>, handle: JoinHandle<T>) {
        exit_tx.send(()).expect("exit_failed");
        handle.await.expect("server failed");
    }

    async fn create_peer_and_connect(target: &DirectoryInfo) -> Connection {
        let exchanger = Exchanger::random();
        let connector = TcpConnector::new(exchanger);

        let connection = connector
            .connect(target.public(), &target.addr())
            .instrument(trace_span!("adder"))
            .await
            .expect("connect failed");

        connection
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

    #[tokio::test]
    async fn corenode_shutdown() {
        init_logger();

        let (exit_dir, handle_dir, dir_info) = setup_dir(next_test_ip4()).await;

        let fake_tob_addr = next_test_ip4();

        let (exit_tx, handle, _) =
            setup_node(next_test_ip4(), dir_info.addr(), fake_tob_addr).await;

        wait_for_server(exit_tx, handle).await;
        wait_for_server(exit_dir, handle_dir).await;
    }

    #[tokio::test]
    async fn config_setup_teardown() {
        init_logger();

        let config = SetupConfig::setup(5).await;
        config.tear_down().await;
    }

    #[tokio::test]
    async fn connect_to_tob() {
        init_logger();

        let config = SetupConfig::setup(1).await;

        let mut connection = create_peer_and_connect(&config.tob_info).await;

        let local = connection.local_addr().expect("getaddr failed");

        async move {
            let txr = TxRequest::Execute();
            connection.send(&txr).await.expect("send failed");

            let resp =
                connection.receive::<String>().await.expect("recv failed");

            assert_eq!(
                resp,
                String::from("Request successfully forwarded to all peers"),
                "invalid response from tob server"
            );
        }
        .instrument(trace_span!("adder", client = %local))
        .await;

        config.tear_down().await;
    }

    #[tokio::test]
    async fn connect_to_corenode() {
        init_logger();

        let config = SetupConfig::setup(1).await;

        let mut connection =
            create_peer_and_connect(&config.corenodes[0].2).await;

        let local = connection.local_addr().expect("getaddr failed");

        async move {
            let txr = TxRequest::GetProof(vec!(String::from("Alan")));
            connection.send(&txr).await.expect("send failed");

            let resp =
                connection.receive::<TxResponse>().await.expect("recv failed");

            assert_eq!(
                resp,
                TxResponse::GetProof(DataTree::new().get_validator()),
                "invalid response from corenode"
            );
        }
        .instrument(trace_span!("adder", client = %local))
        .await;

        config.tear_down().await;
    }

    // #[tokio::test]
    // async fn request_add() {
    //     init_logger();

    //     let config = SetupConfig::setup(1).await;

    //     let mut c_ask =
    //         create_peer_and_connect(&config.corenodes[0].2).await;
    //     let mut c_exec = 

    //     let local = c_ask.local_addr().expect("getaddr failed");

    //     async move {
    //         let txr = TxRequest::GetProof(vec!(String::from("Alan")));
    //             c_ask.send(&txr).await.expect("send failed");

    //         let resp =
    //             c_ask.receive::<TxResponse>().await.expect("recv failed");

    //         assert_eq!(
    //             resp,
    //             TxResponse::GetProof(DataTree::new().get_validator()),
    //             "invalid response from corenode"
    //         );

    //         c_ask.close().await
    //     }
    //     .instrument(trace_span!("adder", client = %local))
    //     .await;

    //     config.tear_down().await;
    // }
}
