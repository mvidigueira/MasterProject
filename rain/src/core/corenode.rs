use std::fmt::Display;
use std::net::SocketAddr;
use std::sync::Arc;

use drop::crypto::key::exchange::{Exchanger, PublicKey};
use drop::net::{
    Connection, DirectoryListener, Listener, TcpConnector, TcpListener,
};

use super::{RecordID, TxRequest, TxResponse, DataTree};

use super::CoreNodeError;

use std::time::Duration;
use tokio::net::ToSocketAddrs;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::task;
use tokio::time::timeout;

use tracing::{error, info, trace_span};
use tracing_futures::Instrument;

type ProtectedTree = Arc<RwLock<DataTree>>;

pub struct CoreNode {
    dir_listener: DirectoryListener,
    tob_addr: SocketAddr,
    exit: Receiver<()>,

    data: ProtectedTree,
}

impl CoreNode {
    pub async fn new<A: ToSocketAddrs + Display>(
        node_addr: SocketAddr,
        dir_addr: A,
        tob_addr: SocketAddr,
        dt: DataTree,
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

                data: Arc::from(RwLock::new(dt)),
            },
            tx,
        );

        Ok(ret)
    }

    // handle this better, don't use an all encompassing error
    pub async fn serve(mut self) -> Result<(), CoreNodeError> {
        let to = Duration::from_secs(1);

        loop {
            if self.exit.try_recv().is_ok() {
                info!("stopping core node");
                break;
            }

            let connection = match timeout(to, self.dir_listener.accept()).await
            {
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
                info!(
                    "new directory connection from TOB server: {}",
                    peer_addr
                );
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

    pub fn public_key(&self) -> &PublicKey {
        self.dir_listener.exchanger().keypair().public()
    }
}

struct TxRequestHandler {
    connection: Connection,
    data: ProtectedTree,
    from_client: bool,
}

impl TxRequestHandler {
    fn new(
        connection: Connection,
        data: ProtectedTree,
        from_client: bool,
    ) -> Self {
        Self {
            connection,
            data,
            from_client,
        }
    }

    async fn handle_get_proof(
        &mut self,
        records: Vec<RecordID>,
    ) -> Result<(), CoreNodeError> {
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
    use super::super::test::*;
    use super::super::{TxRequest, TxResponse, DataTree};

    use tracing::trace_span;
    use tracing_futures::Instrument;

    #[tokio::test]
    async fn corenode_shutdown() {
        init_logger();

        let (exit_dir, handle_dir, dir_info) = setup_dir(next_test_ip4()).await;

        let fake_tob_addr = next_test_ip4();

        let (exit_tx, handle, _) =
            setup_corenode(next_test_ip4(), dir_info.addr(), fake_tob_addr, DataTree::new()).await;

        wait_for_server(exit_tx, handle).await;
        wait_for_server(exit_dir, handle_dir).await;
    }

    #[tokio::test]
    async fn corenode_getproof() {
        init_logger();

        let config = SetupConfig::setup(1, DataTree::new()).await;

        let mut connection =
            create_peer_and_connect(&config.corenodes[0].2).await;

        let local = connection.local_addr().expect("getaddr failed");

        async move {
            let txr = TxRequest::GetProof(vec![String::from("Alan")]);
            connection.send(&txr).await.expect("send failed");

            let resp = connection
                .receive::<TxResponse>()
                .await
                .expect("recv failed");

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

    // move this test to integration tests or client
    #[tokio::test]
    async fn request_add() {
        init_logger();

        let config = SetupConfig::setup(1, DataTree::new()).await;

        let mut c_node = create_peer_and_connect(&config.corenodes[0].2).await;
        let mut c_tob = create_peer_and_connect(&config.tob_info).await;

        let local = c_node.local_addr().expect("getaddr failed");

        async move {
            let txr = TxRequest::GetProof(vec![String::from("Alan")]);
            c_node.send(&txr).await.expect("send failed");

            let resp =
                c_node.receive::<TxResponse>().await.expect("recv failed");

            assert_eq!(
                resp,
                TxResponse::GetProof(DataTree::new().get_validator()),
                "invalid response from corenode"
            );

            let txr = TxRequest::Execute();
            c_tob.send(&txr).await.expect("send failed");

            let resp =
                c_tob.receive::<TxResponse>().await.expect("recv failed");

            assert_eq!(
                resp,
                TxResponse::Execute(String::from(
                    "Request successfully forwarded to all peers"
                )),
                "invalid response from tob server"
            );

            let _ = c_tob.close().await;
            let _ = c_node.close().await;
        }
        .instrument(trace_span!("adder", client = %local))
        .await;

        config.tear_down().await;
    }
}
