use std::fmt::Display;
use std::net::SocketAddr;

use drop::crypto::key::exchange::Exchanger;
use drop::net::DirectoryListener;
use drop::net::{Listener, TcpConnector, TcpListener};

use super::CoreNodeError;

use std::time::Duration;
use tokio::net::ToSocketAddrs;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::time::timeout;

use tracing::{error, info};

struct CoreNode {
    dir_listener: DirectoryListener,
    exit: Receiver<()>,
}

impl CoreNode {
    async fn new<A: ToSocketAddrs + Display>(
        addr: SocketAddr,
        dir_addr: A,
    ) -> Result<(Self, Sender<()>), CoreNodeError> {
        let (tx, rx) = channel();

        let exchanger = Exchanger::random();

        let listener = TcpListener::new(addr, exchanger.clone())
            .await
            .expect("listen failed");

        let connector = TcpConnector::new(exchanger);

        let dir_listener =
            DirectoryListener::new(listener, connector, dir_addr).await?;

        let ret = (
            Self {
                dir_listener: dir_listener,
                exit: rx,
            },
            tx,
        );

        Ok(ret)
    }

    async fn serve(mut self) -> Result<(), CoreNodeError> {
        // handle this better, don't use an all encompassing error
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

            info!("new directory connection from {}", peer_addr);

            connection.send(&String::from("Hello there!")).await?;
            connection.close().await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use drop::net::connector::Connector;

    use drop::crypto::key::exchange::Exchanger;
    use drop::net::{
        Connection, DirectoryConnector, DirectoryInfo, DirectoryServer,
        ListenerError, TcpConnector, TcpListener,
    };

    use tokio::task::{self, JoinHandle};

    use tracing::trace_span;
    use tracing_futures::Instrument;

    use crate::test::*;

    async fn setup_node(
        server_addr: SocketAddr,
        dir_addr: SocketAddr,
    ) -> (Sender<()>, JoinHandle<()>) {
        let (core_server, exit_tx) = CoreNode::new(server_addr, dir_addr)
            .await
            .expect("core node creation failed");

        let handle = task::spawn(
            async move { core_server.serve().await.expect("serve failed") }
                .instrument(trace_span!("directory_serve")),
        );

        (exit_tx, handle)
    }

    async fn setup_dir(
        dir_addr: SocketAddr,
    ) -> (
        Sender<()>,
        JoinHandle<Result<(), ListenerError>>,
        DirectoryInfo,
    ) {
        let exchanger = Exchanger::random();
        let dir_public = exchanger.keypair().public().clone();
        let tcp = TcpListener::new(dir_addr, exchanger)
            .await
            .expect("bind failed");
        let (dir, exit_dir) = DirectoryServer::new(tcp);
        let handle_dir = tokio::task::spawn(async move { dir.serve().await });

        let dir_info = DirectoryInfo::from((dir_public, dir_addr));
        (exit_dir, handle_dir, dir_info)
    }

    async fn wait_for_server<T>(exit_tx: Sender<()>, handle: JoinHandle<T>) {
        exit_tx.send(()).expect("exit_failed");
        handle.await.expect("server failed");
    }

    async fn create_peer_and_connect(dir_info: &DirectoryInfo) -> Connection {
        let exchanger = Exchanger::random();
        let connector = TcpConnector::new(exchanger);
        let mut dir_connector = DirectoryConnector::new(connector);

        let corenodes = dir_connector
            .wait(1, dir_info)
            .await
            .expect("directory wait error");

        let remote_info = corenodes.get(0).unwrap();

        let mut connection = dir_connector
            .connect(remote_info.public(), dir_info)
            .instrument(trace_span!("adder"))
            .await
            .expect("connect failed");

        let local = connection.local_addr().expect("getaddr failed");

        async move {
            let resp =
                connection.receive::<String>().await.expect("recv failed");

            assert_eq!(
                resp,
                String::from("Hello there!"),
                "invalid response from corenode"
            );

            connection
        }
        .instrument(trace_span!("adder", client = %local))
        .await
    }

    #[tokio::test]
    async fn corenode_shutdown() {
        init_logger();

        let (exit_dir, handle_dir, dir_info) = setup_dir(next_test_ip4()).await;

        let (exit_tx, handle) =
            setup_node(next_test_ip4(), dir_info.addr()).await;

        wait_for_server(exit_tx, handle).await;
        wait_for_server(exit_dir, handle_dir).await;
    }

    #[tokio::test]
    async fn connect_to_corenode() {
        init_logger();

        let (exit_dir, handle_dir, dir_info) = setup_dir(next_test_ip4()).await;

        let (exit_tx, corenode_handle) =
            setup_node(next_test_ip4(), dir_info.addr()).await;

        create_peer_and_connect(&dir_info).await;

        wait_for_server(exit_tx, corenode_handle).await;
        wait_for_server(exit_dir, handle_dir).await;
    }
}
