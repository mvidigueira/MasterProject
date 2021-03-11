use drop::crypto::key::exchange::{Exchanger};
use drop::net::{TcpConnector, Connector, DirectoryInfo};
use std::pin::Pin;

use crate::corenode::TobRequest;

use tokio::sync::{mpsc, oneshot};
use tokio::{task};
use tracing::{error, info};

use futures::{task::Context, task::Poll, Stream};
use tokio_stream::wrappers::ReceiverStream;

use futures::{
    select,
    FutureExt,
};

pub struct TobDeliverer {
    receiver: Pin<Box<ReceiverStream<TobRequest>>>,
    exit: Option<oneshot::Sender<()>>,
}

impl TobDeliverer {
    pub async fn new(
        exchanger: Exchanger,
        tob_info: DirectoryInfo,
    ) -> Self {
        let connector = TcpConnector::new(exchanger);
        

        let (tx, rx) = mpsc::channel::<TobRequest>(100);
        let (term, exit) = oneshot::channel();

        task::spawn(async move {
            let mut exit = exit.fuse();
            let addr = tob_info.addr();

            loop {
                let mut connection = select! {
                    _ = exit => {
                        info!("directory server exiting...");
                        return;
                    }
                    a = connector.connect(tob_info.public(), &addr).fuse() => {
                        match a {
                            Err(_) => continue,
                            Ok(connection) => {
                                info!("Established connection with tob");
                                connection
                            }
                        } 
                    }
                };

                loop {
                    select! {
                        _ = exit => {
                            info!("directory server exiting...");
                            return;
                        }
                        a = connection.receive::<TobRequest>().fuse() => {
                            match a {
                                Err(_) => {
                                    error!("TobRequest receiving failed");
                                    continue;
                                }
                                Ok(req) => {
                                    if let Err(_) = tx.send(req).await {
                                        error!("error sending request, receiver dropped");
                                        return;
                                    }
                                    info!("Tob request received");
                                }
                            }
                        }
                    }
                };
            };

        });

        Self {
            receiver: Box::pin(ReceiverStream::new(rx)),
            exit: Some(term),
        }
    }
}

impl Drop for TobDeliverer {
    fn drop(&mut self) {
        let _ = self.exit.take().unwrap().send(());
    }
}

impl Stream for TobDeliverer {
    type Item = TobRequest;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.receiver.as_mut().poll_next(cx)
    }
}
