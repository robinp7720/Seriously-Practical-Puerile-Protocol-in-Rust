use crate::connection::Connection;
use crate::constants::MAX_PACKET_SIZE;
use crate::packet::{Packet, PacketFlags, PrimaryHeader};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

pub struct ConnectionManager {
    connections: Arc<Mutex<HashMap<u32, Connection>>>,
    connection_queue: Arc<Mutex<Vec<Connection>>>,
    socket: UdpSocket,
}

impl ConnectionManager {
    pub fn new(socket: UdpSocket) -> Self {
        ConnectionManager {
            socket,
            connections: Arc::new(Mutex::new(HashMap::new())),
            connection_queue: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn start(&self) {
        let socket = self.socket.try_clone().unwrap();

        let connection_queue = Arc::clone(&self.connection_queue);

        thread::spawn(move || loop {
            let mut buf = [0; MAX_PACKET_SIZE];

            loop {
                println!("Waiting for a new packet");
                let (amt, src) = socket.recv_from(&mut buf).unwrap();

                let packet = Packet::from_bytes(&buf[..amt]);

                // If the connection id is 0, it means that we are receiving a new connection
                // request.
                // Therefore, we need to add the new connection request to the connection queue.
                if packet.get_id() == 0 {
                    println!("We received a new init packet!");

                    let mut connection_queue = connection_queue.lock().unwrap();

                    let connection = Connection::new(src, socket.try_clone().unwrap());
                    connection.send_init_ack();
                    connection_queue.push(connection);

                    continue;
                }

                if packet.is_init() && packet.is_ack() {
                    println!("We received a new init ack packet!");

                    continue;
                }

                // Push the received packet to the respective connection
                println!("We received a new packet!");
                println!("{:?}", packet);
            }
        });
    }

    pub fn accept(&self) -> Connection {
        let connection_queue = Arc::clone(&self.connection_queue);

        loop {
            match connection_queue.lock().unwrap().pop() {
                Some(connection) => {
                    self.connections
                        .lock()
                        .unwrap()
                        .insert(connection.get_connection_id(), connection);

                    // TODO: Return reference to this connection
                    //return connection;
                }
                None => {}
            }
        }
    }

    pub fn connect<A: ToSocketAddrs>(&self, addr: A) {
        // We want to initiate a new connection.
        // To do this, we need to send an init packet to the server

        let mut flags = PacketFlags::new(0);
        flags.init = true;

        let packet = Packet::new(PrimaryHeader::new(0, 0, 0, 0, flags), None, None, vec![]);

        println!("Sending packet: {:?}", packet);

        let payload = packet.to_bytes();
        &self.socket.send_to(&*payload, addr);

        // Wait for a response
        loop {}
    }
}
