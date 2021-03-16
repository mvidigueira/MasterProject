use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task;
use tokio::sync::{mpsc, oneshot};

use futures::{
    select,
    FutureExt,
};
use tracing::{info, error};

use drop::crypto::key::exchange::{Exchanger};
use drop::net::DirectoryInfo;

use crate::corenode::{TobRequest};
use super::TobServerError;
use super::managers::{NodeConnectionManager, UserConnectionManager};

use hbbft::queueing_honey_badger::{
    QueueingHoneyBadger,
    QueueingHoneyBadgerBuilder,
    Step,
};
use hbbft::dynamic_honey_badger::{
    DynamicHoneyBadgerBuilder,
    Message,
};

use hbbft::{NetworkInfo, PubKeyMap, Target, thread_rng_hbbft_compat};



pub struct TobServer {
    request_stream: mpsc::Receiver<TobRequest>,
    outgoing_message_stream: mpsc::Sender<(usize, Message<usize>)>,
    incoming_message_stream: mpsc::Receiver<(usize, Message<usize>)>,

    state_machine: QueueingHoneyBadger<TobRequest, usize, Vec<TobRequest>>,
    first_step: Step<TobRequest, usize>,
    num_nodes: usize,

    ucm_exit: oneshot::Sender<()>,
    exit: oneshot::Receiver<()>,
}

impl TobServer {
    pub async fn new(
        user_addr: SocketAddr,

        tob_addr: SocketAddr,
        exchanger: Exchanger,
        observers: Vec<(DirectoryInfo, hbbft::crypto::PublicKey)>,
        validators: Vec<(DirectoryInfo, hbbft::crypto::PublicKey)>,

        our_key: hbbft::crypto::SecretKey,
        network_info: NetworkInfo<usize>,
    ) -> Result<(Self, oneshot::Sender<()>), TobServerError> {
        let (tx, rx) = oneshot::channel();

        let (ucm, request_stream, ucm_exit) = UserConnectionManager::new(user_addr, exchanger.clone()).await;

        let (ncm, incoming_messages, outgoing_messages) = NodeConnectionManager::new(
            tob_addr, 
            exchanger, 
            observers.iter().map(|x| x.0.public().clone()).collect(), 
            validators.iter().map(|x| x.0.public().clone()).collect()
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

        let num_nodes = validators.len() + observers.len();
        let mut v = validators.clone();
        v.extend(observers.clone().iter());

        let pk_map: PubKeyMap<usize> = Arc::new(v.iter().map(|x| x.1).enumerate().collect());
        let dhb = DynamicHoneyBadgerBuilder::new().build(network_info, our_key, pk_map);
        let mut rng = thread_rng_hbbft_compat();
        let (qhb, s) = QueueingHoneyBadgerBuilder::new(dhb).build(&mut rng).unwrap();

        let s = Self {
            request_stream: request_stream,
            outgoing_message_stream: outgoing_messages,
            incoming_message_stream: incoming_messages,

            state_machine: qhb,
            first_step: s,
            num_nodes: num_nodes,

            ucm_exit: ucm_exit,
            exit: rx,
        };

        Ok((s, tx))
    }

    pub async fn serve(mut self) -> Result<(), TobServerError> {
        Self::process_step(&mut self.outgoing_message_stream, self.first_step, self.num_nodes).await;

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
                            let mut s = thread_rng_hbbft_compat();
                            match self.state_machine.push_transaction(request, &mut s) {
                                Err(e) => {
                                    error!("State machine error when taking request: {:?}", e);
                                }
                                Ok(s) => {
                                    Self::process_step(&mut self.outgoing_message_stream, s, self.num_nodes).await;
                                }
                            }
                        }
                    } 
                }
                b = self.incoming_message_stream.recv().fuse() => {
                    match b {
                        None => unreachable!(),
                        Some((i, m)) => {
                            let mut s = thread_rng_hbbft_compat();
                            match self.state_machine.handle_message(&i, m, &mut s) {
                                Err(e) => {
                                    error!("State machine error when taking message: {:?}", e);
                                }
                                Ok(s) => {
                                    Self::process_step(&mut self.outgoing_message_stream, s, self.num_nodes).await;
                                }
                            }
                        }
                    } 
                }
            };
        }
    }

    async fn process_step(outgoing_messages: &mut mpsc::Sender<(usize, Message<usize>)>, s: Step<TobRequest, usize>, num_ids: usize) {
        use std::collections::BTreeSet;

        for m in s.messages {
            let mut ids: Vec<usize> = match m.target {
                Target::Nodes(n) => {
                    n.iter().cloned().collect()
                }
                Target::AllExcept(n) => {
                    let b: BTreeSet<usize> = (0..num_ids).collect();
                    b.difference(&n).cloned().collect()
                }
            };

            for i in ids.drain(..) {
                if let Err(_) = outgoing_messages.send((i, m.message.clone())).await {
                    unreachable!();
                }
            }
        }

        ()
    }
}