use std::net::SocketAddr;
use std::sync::Arc;

use drop::crypto::key::exchange::{Exchanger, PublicKey};
use drop::net::{
    Connection, DirectoryInfo, Listener, ListenerError,
    TcpConnector, TcpListener,
};

use super::{TobRequest, TobResponse};
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
        exchanger: Exchanger,
        mut corenodes_info: Vec<DirectoryInfo>,
    ) -> Result<(Self, Sender<()>), TobServerError> {
        let (tx, rx) = channel();

        let listener = TcpListener::new(tob_addr, exchanger.clone())
            .await
            .expect("listen failed");

        debug!("successfully connected to corenodes");

        let connector = TcpConnector::new(exchanger);

        let sys = System::new_with_connector_zipped(
            &connector,
            corenodes_info.drain(..).map(|info| (*info.public(), info.addr())),
        )
        .await;

        let (bebs, _) = BestEffort::with::<TobRequest>(sys);

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
        txr: TobRequest,
    ) -> Result<(), TobServerError> {
        if let Some(v) = self.beb.write().await.broadcast(&txr).await {
            if v.len() > 0 {
                let _ = self
                    .connection
                    .send(&TobResponse::Result(String::from(
                        "Error forwarding to peers",
                    )))
                    .await;
                return Err(BroadcastError::new().into());
            }
        } else {
            error!("Broadcast instance not usable anymore!");
            return Err(BroadcastError::new().into());
        }

        let _ = self
            .connection
            .send(&TobResponse::Result(String::from(
                "Request successfully forwarded to all peers",
            )))
            .await;

        Ok(())
    }

    async fn serve(mut self) -> Result<(), TobServerError> {
        while let Ok(txr) = self.connection.receive::<TobRequest>().await {
            self.handle_broadcast(txr).await?;
        }

        self.connection.close().await?;

        info!("end of TOB connection");

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::super::test::*;
    use super::super::{DataTree, TobRequest, TobResponse};

    use tracing::trace_span;
    use tracing_futures::Instrument;
    use drop::crypto::key::exchange::Exchanger;

    #[tokio::test]
    async fn tob_shutdown() {
        init_logger();

        let (exit_dir, handle_dir, _) = setup_dir(next_test_ip4()).await;
        let (exit_tob, handle_tob, _) =
            setup_tob(next_test_ip4(), Exchanger::random(), vec!()).await;

        wait_for_server(exit_tob, handle_tob).await;
        wait_for_server(exit_dir, handle_dir).await;
    }

    #[tokio::test]
    async fn tob_forwarding() {
        init_logger();

        let config = SetupConfig::setup(get_balanced_prefixes(1), DataTree::new(), 10).await;

        let mut connection = create_peer_and_connect(&config.tob_info).await;

        let local = connection.local_addr().expect("getaddr failed");

        async move {
            let txr = TobRequest::Apply(get_example_tobpayload());
            connection.send(&txr).await.expect("send failed");

            let resp = connection
                .receive::<TobResponse>()
                .await
                .expect("recv failed");

            assert_eq!(
                resp,
                TobResponse::Result(String::from(
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
