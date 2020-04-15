use std::net::SocketAddr;

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

use tracing::{error, info};

pub struct TobServer {
    listener: Box<dyn Listener<Candidate = SocketAddr>>,
    beb: BestEffort<TxRequest>,
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
                beb: beb,
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

            self.forward_request(connection).await?;
        }

        Ok(())
    }

    async fn forward_request(&mut self, mut connection: Connection) -> Result<(), TobServerError> {
        let txr: TxRequest = connection.receive().await.expect("recv failed"); // todo: handle receive gracefully
    
        if let Err(_) = self.beb.broadcast(&txr).await {
            return Err(BroadcastError::new().into());
        }

        connection.send(&String::from("Request successfully forwarded to all peers")).await?;
        connection.close().await?;

        Ok(())
    }

    pub fn public_key(&self) -> &PublicKey {
        self.listener.exchanger().keypair().public()
    }
}