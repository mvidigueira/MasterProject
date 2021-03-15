

use hbbft::queueing_honey_badger::{
    QueueingHoneyBadger,
    QueueingHoneyBadgerBuilder,
};
use hbbft::dynamic_honey_badger::{
    DynamicHoneyBadger,
    DynamicHoneyBadgerBuilder,
    Message,
};
use hbbft::transaction_queue::TransactionQueue;

use hbbft::{NetworkInfo};
use rand::{Rng, thread_rng};

//use hbbft::



pub struct TobServer {
    request_stream: mpsc::Receiver<TobRequest>,
    outgoing_message_stream: mpsc::Sender<(PublicKey, Message<PublicKey>)>,
    incoming_message_stream: mpsc::Receiver<(PublicKey, Message<PublicKey>)>,

    state_machine: QueueingHoneyBadger<TobRequest, PublicKey, Vec<TobRequest>>,

    exit: oneshot::Receiver<()>,
}

impl TobServer {
    pub async fn new(
        user_addr: SocketAddr,
        tob_addr: SocketAddr,
        exchanger: Exchanger,
        observers: Vec<DirectoryInfo>,
        validators: Vec<DirectoryInfo>,

        network_info: NetworkInfo<usize>,
    ) -> Result<(Self, oneshot::Sender<()>), TobServerError> {
        let (tx, rx) = oneshot::channel();

        let (ucm, request_stream, exit) = UserConnectionManager::new(user_addr, exchanger.clone()).await;

        let (ncm, incoming_messages, outgoing_messages) = NodeConnectionManager::new(
            tob_addr, 
            exchanger, 
            observers.iter().map(|x| x.public().clone()).collect(), 
            validators.iter().map(|x| x.public().clone()).collect()
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

        let dhb = DynamicHoneyBadgerBuilder::new().build(network_info);
        let mut rng = thread_rng();
        let qhb = QueueingHoneyBadgerBuilder::new(dhb).build(&mut rng);

        let s = Self {
            request_stream: request_stream,
            outgoing_message_stream: outgoing_messages,
            incoming_message_stream: incoming_messages,



            exit: rx,
        };

        Ok((s, tx))
    }

    // handle this better, don't use an all encompassing error
//    pub async fn serve(mut self) -> Result<(), TobServerError> {
//        
//    }
}