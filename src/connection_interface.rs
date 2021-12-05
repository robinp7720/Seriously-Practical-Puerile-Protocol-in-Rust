use std::sync::mpsc::{Receiver, Sender};

pub struct ConnectionInterface {
    sender: Sender<Vec<u8>>,
    receiver: Receiver<Vec<u8>>,
}

impl ConnectionInterface {
    pub fn new(sender: Sender<Vec<u8>>, receiver: Receiver<Vec<u8>>) -> Self {
        ConnectionInterface { sender, receiver }
    }
}
