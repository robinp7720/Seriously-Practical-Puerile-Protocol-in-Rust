use crate::connection::Connection;
use crate::constants::MAX_PACKET_SIZE;
use crate::packet::Packet;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::Mutex;
use std::thread;

pub struct ConnectionManager {
    connections: Mutex<HashMap<u32, Connection>>,
    socket: Mutex<UdpSocket>,
}

impl ConnectionManager {
    pub fn new(socket: UdpSocket) -> Self {
        ConnectionManager {
            socket: Mutex::new(socket),
            connections: Mutex::new(HashMap::new()),
        }
    }

    pub fn start(&self) {
        let socket = self.connections.get_mut();

        thread::spawn(move || loop {
            let mut buf = [0; MAX_PACKET_SIZE];

            loop {
                let (amt, src) = socket.recv_from(&mut buf).unwrap();
                let packet = Packet::from_bytes(&buf[..amt]);

                //self.receive_delegate(packet);
            }
        });
    }

    pub fn accept(&self) {
        loop {
            let mut buf = [0; MAX_PACKET_SIZE];

            let (amt, src) = self.socket.lock().unwrap().recv_from(&mut buf).unwrap();
            let packet = Packet::from_bytes(&buf[..amt]);

            if packet.get_id() == 0 {
                break;
            }

            self.receive_delegate(packet);
        }

        // Initiate new connection
    }

    fn add_connection(&mut self, connection: Connection) -> u32 {
        let id = self.connections.len() as u32;
        self.connections.insert(id, connection);
        id
    }

    fn get_connection(&mut self, id: u32) -> Option<&mut Connection> {
        self.connections.get_mut(&id)
    }

    fn remove_connection(&mut self, id: u32) -> Option<Connection> {
        self.connections.remove(&id)
    }

    fn receive_delegate(&mut self, packet: Packet) {
        let id = packet.get_id();
        if let Some(connection) = self.get_connection(id) {
            connection.receive(packet);
        }
    }
}
