use crate::corenode::TobRequest;
use futures::Stream;

pub trait TobDeliver {
    fn stream(&self) -> &dyn Stream<Item = TobRequest>;
}