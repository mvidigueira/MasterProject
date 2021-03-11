use std::collections::{HashMap, hash_map::Entry};
use std::net::SocketAddr;

use drop::crypto::key::exchange::{Exchanger, PublicKey};
use drop::net::{
    Connection, ConnectionRead, ConnectionWrite, Listener, TcpListener,
};

use crate::corenode::{TobRequest};

use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use super::{TobServerError};

use futures::{
    select,
    FutureExt,
};

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task;

use tracing::{error, info, trace_span};
use tracing_futures::Instrument;


struct ReadConnectionHandler<T, M: Send + Debug + for<'de> Deserialize<'de>> {
    connection: T,
    q_tx: mpsc::Sender<M>,
}

impl<T, M: Send + Debug + for<'de> Deserialize<'de>>
    ReadConnectionHandler<T, M>
{
    pub fn new(connection: T, q_tx: mpsc::Sender<M>) -> Self {
        Self { connection, q_tx }
    }
}

impl<M: Send + Debug + for<'de> Deserialize<'de>>
    ReadConnectionHandler<Connection, M>
{
    pub async fn run(mut self) -> Result<(), TobServerError> {
        while let Ok(txr) = self.connection.receive::<M>().await {
            if let Err(_) = self.q_tx.send(txr).await {
                info!("Receive end has closed");
                break;
            }
        }
        self.connection.close().await?;
        info!("End of read connection");
        Ok(())
    }
}

impl<M: Send + Debug + for<'de> Deserialize<'de>>
    ReadConnectionHandler<ConnectionRead, M>
{
    pub async fn run(mut self) -> Result<(), TobServerError> {
        while let Ok(txr) = self.connection.receive::<M>().await {
            if let Err(_) = self.q_tx.send(txr).await {
                info!("Receive end has closed");
                break;
            }
        }
        info!("End of read connection");
        Ok(())
    }
}

struct WriteConnectionHandler<T, M>
where
    M: Serialize + Send + Sync + Debug 
{
    connection: T,
    q_rx: mpsc::Receiver<M>,
}

impl<T, M> WriteConnectionHandler<T, M>
where
    M: Serialize + Send + Sync + Debug 
{
    pub fn new(connection: T, q_rx: mpsc::Receiver<M>) -> Self {
        Self { connection, q_rx }
    }
}

impl<M> WriteConnectionHandler<Connection, M>
where
    M: Serialize + Send + Sync + Debug  
{
    pub async fn run(mut self) -> Result<(), TobServerError> {
        while let Some(txr) = self.q_rx.recv().await {
            self.connection.send(&txr).await?;
        }
        self.connection.close().await?;
        info!("End of write connection");
        Ok(())
    }
}

impl<M> WriteConnectionHandler<ConnectionWrite, M>
where 
    M: Serialize + Send + Sync + Debug
{
    pub async fn run(mut self) -> Result<(), TobServerError> {
        while let Some(txr) = self.q_rx.recv().await {
            self.connection.send(&txr).await?;
        }
        info!("End of write connection");
        Ok(())
    }
}

pub struct UserConnectionManager {
    listener: Box<dyn Listener<Candidate = SocketAddr>>,
    request_queue_tx: mpsc::Sender<TobRequest>,
    exit: oneshot::Receiver<()>,
}

impl UserConnectionManager {
    /// Returns a UserConnectionManager, a stream of TobRequests coming from users,
    /// and a Sender which terminates the serving task.
    pub async fn new(
        user_addr: SocketAddr,
        exchanger: Exchanger,
    ) -> (Self, mpsc::Receiver<TobRequest>, oneshot::Sender<()>) {
        let (tx, rx) = oneshot::channel();
        let (q_tx, q_rx) = mpsc::channel::<TobRequest>(100);
        let listener = TcpListener::new(user_addr, exchanger)
            .await
            .expect("listen failed");
        let s = Self {
            listener: Box::new(listener),
            request_queue_tx: q_tx,
            exit: rx,
        };

        (s, q_rx, tx)
    }

    pub async fn run(mut self) -> Result<(), TobServerError> {
        let mut exit = self.exit.fuse();

        loop {
            let connection = select! {
                _ = exit => {
                    info!("directory server exiting...");
                    return Ok(());
                }
                a = self.listener.accept().fuse() => {
                    match a {
                        Err(e) => {
                            error!("failed to accept incoming connection: {}", e);
                            continue;
                        },
                        Ok(connection) => {
                            connection
                        }
                    } 
                }
            };
            let peer_addr = connection.peer_addr();

            let q = self.request_queue_tx.clone();

            task::spawn(
                async move {
                    let request_handler = ReadConnectionHandler::new(
                        connection,
                        q,
                    );

                    if let Err(_) = request_handler.run().await {
                        error!("failed request handling");
                    }
                }
                .instrument(
                    trace_span!("tob_request_receiver", client = ?peer_addr),
                ),
            );
        }
    }
}

pub struct NodeConnectionManager<M1, M2>
where
    M1: for<'de> Deserialize<'de> + Send + Debug,
    M2: Serialize + Send + Sync + Debug,
{
    listener: Box<dyn Listener<Candidate = SocketAddr>>,
    receive_queue_tx: mpsc::Sender<(usize, M1)>,
    send_queue_rx: mpsc::Receiver<(usize, M2)>,

    allowed_observer_nodes: Vec<PublicKey>,
    validator_nodes: Vec<PublicKey>,
    write_connections: HashMap<usize, mpsc::Sender<M2>>,
}

impl<M1, M2> NodeConnectionManager<M1, M2>
where 
    M1: for<'de> Deserialize<'de> + Send + Debug + 'static,
    M2: Serialize + Send + Sync + Debug + 'static,
{
    /// Returns a NodeConnectionManager, an output stream of M1 coming from nodes,
    /// an input stream of (PublicKey, M2), and a Sender which terminates the running task.
    /// Each M2 will be sent to the node with the associated PublicKey in order.
    pub async fn new(
        tob_addr: SocketAddr,
        exchanger: Exchanger,
        mut allowed_observer_nodes: Vec<PublicKey>,
        mut validator_nodes: Vec<PublicKey>,
    ) -> (
        Self,
        mpsc::Receiver<(usize, M1)>,
        mpsc::Sender<(usize, M2)>,
    ) {
        let write_connections = HashMap::new();
        let listener = TcpListener::new(tob_addr, exchanger)
            .await
            .expect("listen failed");

        let (q1_tx, q1_rx) = mpsc::channel::<(usize, M1)>(100);
        let (q2_tx, q2_rx) = mpsc::channel::<(usize, M2)>(100);

        allowed_observer_nodes.sort();
        validator_nodes.sort();

        let s = Self {
            listener: Box::new(listener),
            receive_queue_tx: q1_tx,
            send_queue_rx: q2_rx,

            allowed_observer_nodes: allowed_observer_nodes,
            validator_nodes: validator_nodes,
            write_connections: write_connections,
        };

        (s, q1_rx, q2_tx)
    }

    /// run terminates when the mpsc::Sender returned in Self::new() is dropped
    pub async fn run(mut self) -> Result<(), TobServerError> {
        loop {
            let mut connection = select! {
                // When we have to send a message
                a = self.send_queue_rx.recv().fuse() => {
                    match a {
                        None => {
                            info!("directory server exiting...");
                            return Ok(());
                        }
                        Some((pk, m)) => {
                            match self.write_connections.entry(pk) {
                                Entry::Vacant(_) => {
                                    error!("cannot send message to node {:?}: connection doesn't exist", pk);
                                },
                                Entry::Occupied(mut e) => {
                                    match e.get_mut().send(m).await {
                                        Err(_) => {
                                            error!("cannot send message to node {:?}: connection has been closed", pk);
                                            e.remove_entry();
                                        }
                                        _ => (),
                                    }
                                }
                            }
                            continue;
                        }
                    }
                }
                // When receiving an incoming connection from an Observer or Validator
                a = self.listener.accept().fuse() => {
                    match a {
                        Err(e) => {
                            error!("failed to accept incoming connection: {}", e);
                            continue;
                        },
                        Ok(connection) => {
                            connection
                        }
                    } 
                }
            };

            let p_key = match connection.remote_key() {
                None => continue,
                Some(p) => p,
            };

            if self.validator_nodes.contains(&p_key) {
                let (read, write) = connection.split().unwrap();

                let (tx, rx) = mpsc::channel::<M2>(100);
                task::spawn(
                    async move {
                        let request_handler = WriteConnectionHandler::new(
                            write,
                            rx,
                        );

                        request_handler.run().await
                    }
                );
                let i = match self.validator_nodes.binary_search(&p_key) {
                    Ok(i) => i,
                    Err(_) => unreachable!(),
                };
                self.write_connections.insert(i, tx);

                let tx = self.receive_queue_tx.clone();
                task::spawn(
                    async move {
                        let request_handler = ReadConnectionHandler::new(
                            read,
                            tx,
                        );

                        request_handler.run().await
                    }.instrument(
                        trace_span!("tob_validator_reader", validator = %&p_key),
                    ),
                );
            } else if self.allowed_observer_nodes.contains(&p_key) {
                let (tx, rx) = mpsc::channel::<M2>(100);
                task::spawn(
                    async move {
                        let request_handler = WriteConnectionHandler::new(
                            connection,
                            rx,
                        );

                        request_handler.run().await
                    }.instrument(
                        trace_span!("tob_observer_writer", observer = %&p_key),
                    ),
                );
                let i = match self.allowed_observer_nodes.binary_search(&p_key) {
                    Ok(i) => i,
                    Err(_) => unreachable!(),
                };
                self.write_connections.insert(i, tx);
            } else {
                let _ = connection.close().await;
            }
        }
    }
}