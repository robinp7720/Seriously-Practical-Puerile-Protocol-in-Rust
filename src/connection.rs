use crate::packet::Packet;
use std::net::SocketAddr;
use std::net::UdpSocket;

pub struct Connection {
    addr: SocketAddr,
    socket: UdpSocket,
    connection_id: u32,
}

impl Connection {
    pub fn new(addr: SocketAddr, socket: UdpSocket, connection_id: u32) -> Connection {
        Connection {
            addr,
            socket,
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
