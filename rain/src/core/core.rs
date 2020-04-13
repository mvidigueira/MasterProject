use std::net::{Ipv4Addr, SocketAddr};

use drop::crypto::key::exchange::{Exchanger, PublicKey};
use drop::net::{Connection, Listener, TcpConnector, TcpListener};

use super::CoreNodeError;

use std::time::Duration;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::time::timeout;

use tracing::{debug, error, info, trace, trace_span, warn};
use tracing_futures::Instrument;

struct CoreNode {
    listener: Box<dyn Listener<Candidate = SocketAddr>>,
    exit: Receiver<()>,
}

impl CoreNode {
    fn new<L: Listener<Candidate = SocketAddr> + 'static>(
        listener: L,
    ) -> (Self, Sender<()>) {
        let (tx, rx) = channel();

        (
            Self {
                exit: rx,
                listener: Box::new(listener),
            },
            tx,
        )
    }

    pub async fn serve(mut self) -> Result<(), CoreNodeError> {
        // handle this better, don't use an all encompassing error
        let to = Duration::from_secs(1);

        loop {
            if self.exit.try_recv().is_ok() {
                info!("stopping core node");
                break;
            }

            let mut connection = match timeout(to, self.listener.accept()).await
            {
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
    use drop::net::{TcpConnector, TcpListener};

    use futures::future;

    use tokio::task::{self, JoinHandle};

    use crate::test::*;

    async fn setup_node(
        server: SocketAddr,
        exchanger: Exchanger,
    ) -> (Sender<()>, JoinHandle<()>) {
        let listener = TcpListener::new(server, exchanger)
            .await
            .expect("listen failed");
        let (core_server, exit_tx) = CoreNode::new(listener);

        let handle = task::spawn(
            async move { core_server.serve().await.expect("serve failed") }
                .instrument(trace_span!("directory_serve")),
        );

        (exit_tx, handle)
    }

    fn new_peer() -> (PublicKey, SocketAddr) {
        let peer = next_test_ip4();
        let pkey = *Exchanger::random().keypair().public();

        (pkey, peer)
    }

    async fn wait_for_server(exit_tx: Sender<()>, handle: JoinHandle<()>) {
        exit_tx.send(()).expect("exit_failed");
        handle.await.expect("server failed");
    }

    #[tokio::test]
    async fn corenode_shutdown() {
        init_logger();

        let (exit_tx, handle) =
            setup_node(next_test_ip4(), Exchanger::random()).await;

        wait_for_server(exit_tx, handle).await;
    }

    async fn create_peer_and_connect(
        server_pkey: &PublicKey,
        server_addr: &SocketAddr,
    ) -> Connection {
        let connector = TcpConnector::new(Exchanger::random());

        let mut connection = connector
            .connect(&server_pkey, &server_addr)
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
    async fn connect_to_corenode() {
        init_logger();

        let corenode_address = next_test_ip4();
        let exchanger = Exchanger::random();
        let corenode_pkey = exchanger.keypair().public().clone();
        let (exit_tx, corenode_handle) =
            setup_node(corenode_address, exchanger).await;

        create_peer_and_connect(&corenode_pkey, &corenode_address).await;

        wait_for_server(exit_tx, corenode_handle).await;
    }

    // async fn add_peer(
    //     server: SocketAddr,
    //     addr: SocketAddr,
    //     pkey: PublicKey,
    //     connector: &dyn Connector<Candidate = SocketAddr>,
    // ) -> Connection {
    //     let peer = (pkey, addr).into();
    //     let req = Request::Add(peer);

    //     let mut connection = connector
    //         .connect(&pkey, &server)
    //         .instrument(trace_span!("adder"))
    //         .await
    //         .expect("connect failed");
    //     let local = connection.local_addr().expect("getaddr failed");

    //     async move {
    //         connection.send_plain(&req).await.expect("send failed");

    //         let resp = connection
    //             .receive_plain::<Response>()
    //             .await
    //             .expect("recv failed");

    //         assert_eq!(resp, Response::Ok, "invalid response");

    //         connection
    //     }
    //     .instrument(trace_span!("adder", client = %local))
    //     .await
    // }
}
