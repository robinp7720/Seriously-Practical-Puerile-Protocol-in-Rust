use crate::packet::{Packet, PacketFlags, PrimaryHeader};
use std::net::{SocketAddr, UdpSocket};

pub struct Connection {
    addr: SocketAddr,
    connection_id: u32,
    socket: UdpSocket,
}

impl Connection {
    pub fn new(addr: SocketAddr, socket: UdpSocket) -> Connection {
        // Generate a random connection id
        let connection_id = rand::random();

        Connection {
            addr,
            connection_id,
            socket,
        }
    }

    pub fn send_init_ack(&self) {
        let mut flags = PacketFlags::new(0);
        flags.init = true;
        flags.ack = true;

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            vec![],
        );

        println!("Sending init-ack: {:?}", packet);

        let payload = packet.to_bytes();
        &self.socket.send_to(&*payload, self.addr);
    }

    pub fn get_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn get_connection_id(&self) -> u32 {
        self.connection_id
    }

    pub fn receive(&self, packet: Packet) {}
}
