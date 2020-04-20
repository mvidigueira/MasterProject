use std::net::SocketAddr;
use std::sync::Arc;

use drop::crypto::key::exchange::{Exchanger, PublicKey};
use drop::net::{
    Connection, DirectoryConnector, DirectoryInfo, Listener,
    TcpConnector, TcpListener,
};

use super::TxRequest;
use classic::{BestEffort, System, Broadcast};

use super::{TobServerError, BroadcastError};

use std::time::Duration;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::time::timeout;
use tokio::sync::RwLock;
use tokio::task;

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

            let connection = match timeout(to, self.listener.accept()).await
            {
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
                    let request_handler = TobRequestHandler::new(connection, beb);

                    if let Err(_) = request_handler.serve().await {
                        error!("failed request handling");
                    }

                }.instrument(trace_span!("tob_request_receiver", client = %peer_addr)),
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
        Self {connection, beb}
    }

    async fn handle_broadcast(&mut self, txr: TxRequest) -> Result<(), TobServerError> {
        if let Err(_) = self.beb.write().await.broadcast(&txr).await {
            return Err(BroadcastError::new().into());
        }

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