use std::net::SocketAddr;
use std::sync::Arc;

use drop::crypto::key::exchange::{Exchanger, PublicKey};
use drop::net::{
    Connection, DirectoryConnector, DirectoryInfo, Listener, TcpConnector,
    TcpListener,
};

use super::{TxRequest, TxResponse};
use classic::{BestEffort, Broadcast, System};

use super::{BroadcastError, TobServerError};

use std::time::Duration;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::task;
use tokio::time::timeout;

use tracing::{error, info, trace_span};
use tracing_futures::Instrument;

type ProtectedBeb = Arc<RwLock<BestEffort<TxRequest>>>;

pub struct TobServer {
    listener: Box<dyn Listener<Candidate = SocketAddr>>,
    beb: ProtectedBeb,
    exit: Receiver<()>,
}

impl TobServer {
    pub async fn new(
        tob_addr: SocketAddr,
        dir_info: &DirectoryInfo,
        nr_peer: usize,
    ) -> Result<(Self, Sender<()>), TobServerError> {
        let (tx, rx) = channel();

        let exchanger = Exchanger::random();

        let listener = TcpListener::new(tob_addr, exchanger.clone())
            .await
            .expect("listen failed");

        let connector = TcpConnector::new(exchanger.clone());
        let mut dir_connector = DirectoryConnector::new(connector);
        let mut peers = if nr_peer > 0 {
            dir_connector
                .wait(nr_peer, dir_info)
                .await
                .expect("could not wait")
        } else {
            Vec::new()
        };

        drop(dir_connector);

        let connector = TcpConnector::new(exchanger);

        let beb = System::new_with_connector_zipped(
            &connector,
            peers.drain(..).map(|info| (*info.public(), info.addr())),
        )
        .await
        .into();

        let ret = (
            Self {
                listener: Box::new(listener),
                beb: Arc::from(RwLock::new(beb)),
                exit: rx,
            },
            tx,
        );

        Ok(ret)
    }

    // handle this better, don't use an all encompassing error
    pub async fn serve(mut self) -> Result<(), TobServerError> {
        let to = Duration::from_secs(1);

        loop {
            if self.exit.try_recv().is_ok() {
                info!("stopping tob server");
                break;
            }

            let connection = match timeout(to, self.listener.accept()).await {
                Ok(Ok(socket)) => socket,
                Ok(Err(e)) => {
                    error!("failed to accept client connection: {}", e);
                    return Err(e.into());
                }
                Err(_) => continue,
            };

            let peer_addr = connection.peer_addr()?;

            info!("new tob connection from client {}", peer_addr);

            let beb = self.beb.clone();

            task::spawn(
                async move {
                    let request_handler =
                        TobRequestHandler::new(connection, beb);

                    if let Err(_) = request_handler.serve().await {
                        error!("failed request handling");
                    }
                }
                .instrument(
                    trace_span!("tob_request_receiver", client = %peer_addr),
                ),
            );
        }

        Ok(())
    }

    pub fn public_key(&self) -> &PublicKey {
        self.listener.exchanger().keypair().public()
    }
}

struct TobRequestHandler {
    connection: Connection,
    beb: ProtectedBeb,
}

impl TobRequestHandler {
    fn new(connection: Connection, beb: ProtectedBeb) -> Self {
        Self { connection, beb }
    }

    async fn handle_broadcast(
        &mut self,
        txr: TxRequest,
    ) -> Result<(), TobServerError> {
        if let Err(_) = self.beb.write().await.broadcast(&txr).await {
            let _ = self
                .connection
                .send(&TxResponse::Execute(String::from(
                    "Error forwarding to peers",
                )))
                .await;
            return Err(BroadcastError::new().into());
        }

        let _ = self
            .connection
            .send(&TxResponse::Execute(String::from(
                "Request successfully forwarded to all peers",
            )))
            .await;

        Ok(())
    }

    async fn serve(mut self) -> Result<(), TobServerError> {
        while let Ok(txr) = self.connection.receive::<TxRequest>().await {
            info!("Received request {:?}", txr);

            match txr {
                TxRequest::GetProof(_) => {
                    error!("TxRequest::GetProof should be sent directly by a client, not via TOB!");
                }
                TxRequest::Execute() => {
                    self.handle_broadcast(TxRequest::Execute()).await?;
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
    async fn tob_shutdown() {
        init_logger();

        let (exit_dir, handle_dir, dir_info) = setup_dir(next_test_ip4()).await;
        let (exit_tob, handle_tob, _) = setup_tob(next_test_ip4(), &dir_info, 0).await;

        wait_for_server(exit_tob, handle_tob).await;
        wait_for_server(exit_dir, handle_dir).await;
    }

    #[tokio::test]
    async fn tob_forwarding() {
        init_logger();

        let config = SetupConfig::setup(1, DataTree::new()).await;

        let mut connection = create_peer_and_connect(&config.tob_info).await;

        let local = connection.local_addr().expect("getaddr failed");

        async move {
            let txr = TxRequest::Execute();
            connection.send(&txr).await.expect("send failed");

            let resp = connection
                .receive::<TxResponse>()
                .await
                .expect("recv failed");

            assert_eq!(
                resp,
                TxResponse::Execute(String::from(
                    "Request successfully forwarded to all peers"
                )),
                "invalid response from tob server"
            );
        }
        .instrument(trace_span!("adder", client = %local))
        .await;

        config.tear_down().await;
    }
}