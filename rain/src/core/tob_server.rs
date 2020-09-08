use std::net::SocketAddr;
use std::sync::Arc;

use drop::crypto::key::exchange::{Exchanger, PublicKey};
use drop::net::{
    Connection, DirectoryConnector, DirectoryInfo, Listener, TcpConnector,
    TcpListener, ListenerError,
};

use super::{TxRequest, TxResponse};
use classic::{BestEffort, BestEffortBroadcaster, Broadcaster, System};

use super::{BroadcastError, TobServerError};

use futures::future::{self, Either};

use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::task;

use tracing::{debug, error, info, trace_span};
use tracing_futures::Instrument;

type ProtectedBeb = Arc<RwLock<BestEffortBroadcaster>>;

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

        debug!("waiting to connect to corenodes");
        debug!("Directory Info: {:#?}", dir_info);

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

        debug!("successfully connected to corenodes");

        drop(dir_connector);

        let connector = TcpConnector::new(exchanger);



        let sys = System::new_with_connector_zipped(
            &connector,
            peers.drain(..).map(|info| (*info.public(), info.addr())),
        )
        .await;

        let (bebs, _) = BestEffort::with::<TxRequest>(sys);

        let ret = (
            Self {
                listener: Box::new(listener),
                beb: Arc::from(RwLock::new(bebs)),
                exit: rx,
            },
            tx,
        );

        Ok(ret)
    }

    // handle this better, don't use an all encompassing error
    pub async fn serve(mut self) -> Result<(), TobServerError> {
        let mut exit_fut = Some(self.exit);

        loop {
            let (exit, connection) = match Self::poll_incoming(
                self.listener.as_mut(),
                exit_fut.take().unwrap(),
            )
            .await
            {
                PollResult::Error(e) => {
                    error!("failed to accept incoming connection: {}", e);
                    return Err(e.into());
                }
                PollResult::Exit => {
                    info!("directory server exiting...");
                    return Ok(());
                }
                PollResult::Incoming(exit, connection) => (exit, connection),
            };

            exit_fut = Some(exit);

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
    }

    pub fn public_key(&self) -> &PublicKey {
        self.listener.exchanger().keypair().public()
    }

    async fn poll_incoming<L: Listener<Candidate = SocketAddr> + ?Sized>(
        listener: &mut L,
        exit: Receiver<()>,
    ) -> PollResult {
        match future::select(exit, listener.accept()).await {
            Either::Left(_) => PollResult::Exit,
            Either::Right((Ok(connection), exit)) => {
                PollResult::Incoming(exit, connection)
            }
            Either::Right((Err(e), _)) => PollResult::Error(e),
        }
    }
}

enum PollResult {
    Incoming(Receiver<()>, Connection),
    Error(ListenerError),
    Exit,
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
        if let Some(v) = self.beb.write().await.broadcast(&txr).await {
            if v.len() > 0 {
                let _ = self
                .connection
                .send(&TxResponse::Execute(String::from(
                    "Error forwarding to peers",
                )))
                .await;
            return Err(BroadcastError::new().into());
            }
        } else {
            error!("Broadcast instance not usable anymore!");
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
            match txr {
                TxRequest::GetProof(_) => {
                    error!("TxRequest::GetProof should be sent directly by a client, not via TOB!");
                }
                TxRequest::Execute(rt) => {
                    info!("Received request {:?}", rt.rule_record_id);
                    self.handle_broadcast(TxRequest::Execute(rt)).await?;
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
    use super::super::{DataTree, TxRequest, TxResponse};

    use tracing::trace_span;
    use tracing_futures::Instrument;

    #[tokio::test]
    async fn tob_shutdown() {
        init_logger();

        let (exit_dir, handle_dir, dir_info) = setup_dir(next_test_ip4()).await;
        let (exit_tob, handle_tob, _) =
            setup_tob(next_test_ip4(), &dir_info, 0).await;

        wait_for_server(exit_tob, handle_tob).await;
        wait_for_server(exit_dir, handle_dir).await;
    }

    #[tokio::test]
    async fn tob_forwarding() {
        init_logger();

        let config = SetupConfig::setup(1, DataTree::new(), 10).await;

        let mut connection = create_peer_and_connect(&config.tob_info).await;

        let local = connection.local_addr().expect("getaddr failed");

        async move {
            let txr = TxRequest::Execute(get_example_rt());
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
