use std::net::SocketAddr;
use std::sync::Arc;

use drop::crypto::key::exchange::{Exchanger, PublicKey};

use crate::corenode::{TobRequest};

use super::{TobServerError};

use futures::{
    select,
    FutureExt,
};

use tokio::sync::{oneshot, mpsc};
use tokio::task;

use super::managers::{NodeConnectionManager, UserConnectionManager};

use tracing::info;

pub struct TobServer {
    request_stream: mpsc::Receiver<TobRequest>,
    outgoing_messages: mpsc::Sender<(usize, Arc<TobRequest>)>,
    _incoming_messages: mpsc::Receiver<(usize, TobRequest)>,

    num_observers: usize,

    ucm_exit: oneshot::Sender<()>,
    exit: oneshot::Receiver<()>,
}

impl TobServer {
    pub async fn new(
        user_addr: SocketAddr,
        tob_addr: SocketAddr,
        exchanger: Exchanger,
        observers: Vec<PublicKey>,
    ) -> Result<(Self, oneshot::Sender<()>), TobServerError> {
        let (tx, rx) = oneshot::channel();
        let num_observers = observers.len();

        let (ucm, request_stream, ucm_exit) = UserConnectionManager::new(user_addr, exchanger.clone()).await;
        
        let (ncm, incoming_messages, outgoing_messages) = NodeConnectionManager::new(
            tob_addr, 
            exchanger, 
            observers, 
            vec!(),
        ).await;
        
        task::spawn(
            async move {
                ucm.run().await
            } 
        );
        task::spawn(
            async move {
                ncm.run().await
            } 
        );

        let ret = (
            Self {
                request_stream: request_stream,
                outgoing_messages: outgoing_messages,
                _incoming_messages: incoming_messages, 

                num_observers: num_observers,

                ucm_exit: ucm_exit,
                exit: rx,
            },
            tx,
        );

        Ok(ret)
    }

    // handle this better, don't use an all encompassing error
    pub async fn serve(mut self) -> Result<(), TobServerError> {
        let mut exit = self.exit.fuse();
        loop {
            select! {
                _ = exit => {
                    info!("tob server exiting...");
                    let _ = self.ucm_exit.send(());
                    return Ok(());
                }
                a = self.request_stream.recv().fuse() => {
                    match a {
                        None => unreachable!(),
                        Some(request) => {
                            let m = Arc::new(request);
                            for i in 0..self.num_observers {
                                let _ = self.outgoing_messages.send((i, m.clone())).await;
                            }
                        }
                    } 
                }
            };
        }
    }
}

#[cfg(test)]
mod test {
    use crate::corenode::{DataTree, TobRequest};
    use crate::utils::test::*;

    use drop::crypto::key::exchange::Exchanger;
    use tracing::trace_span;
    use tracing_futures::Instrument;

    #[tokio::test]
    async fn tob_shutdown() {
        init_logger();

        let (exit_tob, handle_tob, _) =
            setup_tob(next_test_ip4(), next_test_ip4(), Exchanger::random(), vec![]).await;

        wait_for_server(exit_tob, handle_tob).await;
    }

    #[tokio::test]
    async fn tob_forwarding() {
        init_logger();

        let config =
            RunningConfig::setup(get_balanced_prefixes(1), DataTree::new(), 10)
                .await;

        let mut connection = create_peer_and_connect(&config.tob_info).await;

        let local = connection.local_addr().expect("getaddr failed");

        async move {
            let txr = TobRequest::Apply((
                get_example_tobpayload(),
                get_example_bls_sig_info(),
            ));
            connection.send(&txr).await.expect("send failed");

//            let resp = connection
//                .receive::<TobResponse>()
//                .await
//                .expect("recv failed");

//            assert_eq!(
//                resp,
//                TobResponse::Result(String::from(
//                    "Request successfully forwarded to all peers"
//                )),
//                "invalid response from tob server"
//            );
        }
        .instrument(trace_span!("adder", client = %local))
        .await;

        config.tear_down().await;
    }
}
