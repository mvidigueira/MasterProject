use std::fmt::Display;
use std::net::SocketAddr;

use drop::crypto::key::exchange::{Exchanger, PublicKey};
use drop::net::{DirectoryListener, Listener,
    TcpConnector, TcpListener,
};

use super::CoreNodeError;

use std::time::Duration;
use tokio::net::ToSocketAddrs;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::time::timeout;

use tracing::{error, info};

struct CoreNode {
    dir_listener: DirectoryListener,
    tob_addr: SocketAddr,
    exit: Receiver<()>,
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

            if peer_addr == self.tob_addr {
                info!(
                    "new directory connection from TOB server: {}",
                    peer_addr
                );
            } else {
                info!("new directory connection from client {}", peer_addr);
            }

            connection
                .send(&String::from("Hello from corenode!"))
                .await?;
            connection.close().await?;
        }

        Ok(())
    }

    fn public_key(&self) -> &PublicKey {
        self.dir_listener.exchanger().keypair().public()
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

        let config = SetupConfig::setup(0).await;

        let mut connection = create_peer_and_connect(&config.tob_info).await;

        let local = connection.local_addr().expect("getaddr failed");

        async move {
            let resp =
                connection.receive::<String>().await.expect("recv failed");

            assert_eq!(
                resp,
                String::from("I am the mighty TOB server! I bestow ORDER upon the universe!"),
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
            let resp =
                connection.receive::<String>().await.expect("recv failed");

            assert_eq!(
                resp,
                String::from("Hello from corenode!"),
                "invalid response from corenode"
            );
        }
        .instrument(trace_span!("adder", client = %local))
        .await;

        config.tear_down().await;
    }
}
