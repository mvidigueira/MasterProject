use std::net::SocketAddr;
use drop::crypto::key::exchange::{Exchanger, PublicKey};
use drop::net::{Listener, 
    TcpListener,
};

use crate::corenode::{TobRequest};


use futures::future::{self, Either};

use tokio::sync::{oneshot, mpsc};
use tokio::{task, pin};
use tracing::{error};

use super::TobDeliver;
use futures::Stream;

pub struct TobDeliverer {
    receiver: mpsc::Receiver<TobRequest>,
    exit: Option<oneshot::Sender<()>>, 
}

impl TobDeliverer {
    pub async fn new(addr: SocketAddr, exchanger: Exchanger, tob_pub: PublicKey) -> Self {
        let mut listener = TcpListener::new(addr, exchanger.clone())
            .await
            .expect("listen failed");

        let (mut tx, rx) = mpsc::channel::<TobRequest>(100);
        let (term, exit) = oneshot::channel();

        task::spawn(async move {
            let mut exit_fut = Some(exit);

            let mut connection = loop {
                match future::select(exit_fut.take().unwrap(), listener.accept()).await {
                    Either::Left(_) => return,
                    Either::Right((Ok(mut connection), exit)) => {
                        exit_fut = Some(exit);

                        if Some(tob_pub) == connection.remote_key() {
                            break connection;
                        } else {
                            let _ = connection.close().await;
                        }
                    }
                    Either::Right((Err(e), _)) => {
                        error!("Error receiving TobRequest through tcp: {:?}", e);
                        return;
                    }
                };
            };

            loop {
                let fut = connection.receive();
                pin!(fut);

                match future::select(exit_fut.take().unwrap(), fut).await {
                    Either::Left(_) => return,
                    Either::Right((Ok(res), exit)) => {
                        exit_fut = Some(exit);

                        tx.send(res).await.expect("Sending TobRequest through channel failed");
                    }
                    Either::Right((Err(e), _)) => {
                        error!("Error receiving TobRequest through tcp: {:?}", e);
                        return;
                    }
                };
            }

        });

        Self {
            receiver: rx,
            exit: Some(term),
        }
    }
}

impl Drop for TobDeliverer {
    fn drop(&mut self) {
        let _ = self.exit.take().unwrap().send(());
    }
}

impl TobDeliver for TobDeliverer {
    fn stream(&self) -> &dyn Stream<Item=TobRequest> {
        &self.receiver
    }
}