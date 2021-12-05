use crate::connection::Connection;
use crate::connection_interface::ConnectionInterface;
use crate::constants::MAX_PACKET_SIZE;
use crate::packet::{Packet, PacketFlags, PrimaryHeader};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Mutex;
use std::sync::{mpsc, Arc};
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
        let connections = Arc::clone(&self.connections);

        thread::spawn(move || loop {
            let mut buf = [0; MAX_PACKET_SIZE];

            loop {
                println!("Waiting for a new packet");
                let (amt, src) = socket.recv_from(&mut buf).unwrap();

                let packet = Packet::from_bytes(&buf[..amt]);

                // If the connection id is 0, it means that we are receiving a new connection
                // request.
                // Therefore, we need to add the new connection request to the connection queue.
                if packet.get_connection_id() == 0 && packet.is_init() {
                    println!("We received a new init packet!");

                    // Insert this packet into the new connection queue
                    let mut connection_queue = connection_queue.lock().unwrap();

                    let connection = Connection::new(src, socket.try_clone().unwrap(), None);
                    connection.send_init_ack();
                    connection_queue.push(connection);

                    continue;
                }

                if packet.is_init() && packet.is_ack() {
                    println!("We received a new init ack packet!");

                    let connection = Connection::new(
                        src,
                        socket.try_clone().unwrap(),
                        Some(packet.get_connection_id()),
                    );

                    connections
                        .lock()
                        .unwrap()
                        .insert(connection.get_connection_id(), connection);

                    println!("{:?}", connections.lock().unwrap().keys());

                    continue;
                }

                // Push the received packet to the respective connection
                println!("We received a new packet!");
                println!("{:?}", packet);

                // No new connection needs to be setup.
                // This means that the packet can be handled by the connection with the same
                // connection_id
                connections
                    .lock()
                    .unwrap()
                    .get_mut(&packet.get_connection_id())
                    .unwrap()
                    .receive_packet(packet);
            }
        });
    }

    pub fn accept(&self) -> ConnectionInterface {
        let connection_queue = Arc::clone(&self.connection_queue);

        loop {
            match connection_queue.lock().unwrap().pop() {
                Some(mut connection) => {
                    let (sender_tx, sender_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) =
                        mpsc::channel();
                    let (receiver_tx, receiver_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) =
                        mpsc::channel();

                    connection.bind_channel(sender_rx, receiver_tx);

                    self.connections
                        .lock()
                        .unwrap()
                        .insert(connection.get_connection_id(), connection);

                    return ConnectionInterface::new(sender_tx, receiver_rx);
                }
                None => {}
            }
        }
    }

    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> Result<ConnectionInterface, &str> {
        // We want to initiate a new connection.
        // To do this, we need to send an init packet to the server

        let mut flags = PacketFlags::new(0);
        flags.init = true;

        let packet = Packet::new(PrimaryHeader::new(0, 0, 0, 0, flags), None, None, vec![]);

        println!("Sending packet: {:?}", packet);

        let payload = packet.to_bytes();
        &self.socket.send_to(&*payload, addr);

        // Wait for a response
        loop {
            // TODO: This will only work if the client connects to one server
            //       I'm assuming this won't really be a problem, but it's a limitation non the less
            if self.connections.lock().unwrap().len() == 0 {
                continue;
            }

            break;
        }
        for connection in self.connections.lock().unwrap().values_mut() {
            let (sender_tx, sender_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
            let (receiver_tx, receiver_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();

            connection.bind_channel(sender_rx, receiver_tx);

            return Ok(ConnectionInterface::new(sender_tx, receiver_rx));
        }

        Err("Couldn't connect")
    }
}
