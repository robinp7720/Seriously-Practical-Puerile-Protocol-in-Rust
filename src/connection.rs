use crate::packet::{Packet, PacketFlags, PrimaryHeader};
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Mutex;

pub struct Connection {
    addr: SocketAddr,
    connection_id: u32,
    socket: UdpSocket,
    sender: Option<Receiver<Vec<u8>>>,
    receiver: Option<Sender<Vec<u8>>>,
    incoming: Mutex<Vec<Packet>>,
}

impl Connection {
    pub fn new(addr: SocketAddr, socket: UdpSocket, connection_id: Option<u32>) -> Connection {
        let connection_id = match connection_id {
            None => rand::random(),
            Some(connection_id) => connection_id,
        };

        Connection {
            addr,
            connection_id,
            socket,
            sender: None,
            receiver: None,
            incoming: Mutex::new(vec![]),
        }
    }

    pub fn bind_channel(&mut self, sender: Receiver<Vec<u8>>, receiver: Sender<Vec<u8>>) {
        self.sender = Some(sender);
        self.receiver = Some(receiver);
    }

    pub fn receive_packet(&mut self, packet: Packet) {
        let mut incoming = self.incoming.lock().unwrap();
        incoming.push(packet);
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
