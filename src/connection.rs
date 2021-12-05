use crate::packet::Packet;
use std::net::SocketAddr;

pub struct Connection {
    addr: SocketAddr,
    connection_id: u32,
}

impl Connection {
    pub fn new(addr: SocketAddr) -> Connection {
        // Generate a random connection id
        let connection_id = rand::random();

        Connection {
            addr,
            connection_id,
        }
    }

    pub fn get_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn get_connection_id(&self) -> u32 {
        self.connection_id
    }

    pub fn receive(&self, packet: Packet) {}
}
