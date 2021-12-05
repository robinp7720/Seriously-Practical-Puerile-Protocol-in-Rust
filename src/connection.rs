use crate::packet::{Packet, PacketFlags, PrimaryHeader};
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Mutex;

pub struct Connection {
    addr: SocketAddr,
    connection_id: u32,
    socket: UdpSocket,
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
            incoming: Mutex::new(vec![]),
        }
    }

    pub fn receive_packet(&mut self, packet: Packet) {
        let mut incoming = self.incoming.lock().unwrap();

        println!("we have recevied a data packet! {:?}", packet.get_payload());

        incoming.push(packet);
    }

    pub fn canRecv(&self) -> bool {
        let incoming = self.incoming.lock().unwrap();

        //println!("{}, {}", incoming.len(), incoming.is_empty());

        return !incoming.is_empty();
    }

    pub fn recv(&mut self) -> Vec<u8> {
        let mut incoming = self.incoming.lock().unwrap();
        let mut output: Vec<u8> = Vec::new();

        for packet in incoming.iter() {
            output.append(&mut packet.get_payload());
        }

        incoming.clear();

        return output;
    }

    fn send_packet(&self, packet: Packet) {
        println!("sending packet to: {}", self.addr);
        self.socket.send_to(&*packet.to_bytes(), self.addr);
    }

    pub fn send_data(&self, payload: Vec<u8>) {
        let mut flags = PacketFlags::new(0);

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            payload,
        );

        self.send_packet(packet);
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
