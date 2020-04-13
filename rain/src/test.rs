use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};

use drop::crypto::key::exchange::{Exchanger, PublicKey};
use drop::net::{Connection, Listener, TcpConnector, TcpListener};

use futures::future;

use tokio::task::{self, JoinHandle};

use tracing::info;
use tracing_subscriber::FmtSubscriber;

static PORT_OFFSET: AtomicU16 = AtomicU16::new(0);

/// Initialize an asynchronous logger for test environment
pub fn init_logger() {
    if let Some(level) = env::var("RUST_LOG").ok().map(|x| x.parse().ok()) {
        let subscriber =
            FmtSubscriber::builder().with_max_level(level).finish();

        let _ = tracing::subscriber::set_global_default(subscriber);
    }
}

pub fn next_test_ip4() -> SocketAddr {
    (
        Ipv4Addr::LOCALHOST,
        9000 + PORT_OFFSET.fetch_add(1, Ordering::AcqRel),
    )
        .into()
}

pub fn test_addrs(count: usize) -> Vec<(Exchanger, SocketAddr)> {
    (0..count)
        .map(|_| (Exchanger::random(), next_test_ip4()))
        .collect()
}
