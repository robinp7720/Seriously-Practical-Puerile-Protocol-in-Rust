use crate::connection::Connection;
use crate::constants::MAX_PACKET_SIZE;
use crate::cookie::ConnectionCookie;
use crate::packet::{Packet, PacketFlags, PrimaryHeader};
use std::collections::HashMap;
use std::io::Error;
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

pub struct ConnectionManager {
    connections: Arc<Mutex<HashMap<u32, Arc<Mutex<Connection>>>>>,
    connection_queue: Arc<Mutex<Vec<u32>>>,
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
        self.start_recv_thread();
    }

    fn start_recv_thread(&self) {
        let socket = self.socket.try_clone().unwrap();

        let connection_queue = Arc::clone(&self.connection_queue);
        let connections = Arc::clone(&self.connections);

        // Listening thread
        thread::spawn(move || loop {
            let mut buf = [0; MAX_PACKET_SIZE];

            loop {
                let (amt, src) = socket.recv_from(&mut buf).unwrap();

                let packet = Packet::from_bytes(&buf[..amt]);

                // CLIENT SENDING A CONNECTION REQUEST TO SERVER
                // Here we create the connection object for the server
                // If the connection id is 0, it means that we are receiving a new connection
                // request.
                // Therefore, we need to add the new connection request to the connection queue.
                if packet.get_connection_id() == 0 && packet.is_init() {
                    // Insert this packet into the new connection queue
                    let mut connection_queue = connection_queue.lock().unwrap();

                    let mut connection =
                        Connection::new(src, socket.try_clone().unwrap(), None, None);
                    connection.start_threads();
                    connection.send_init_ack();

                    let connection_id = connection.get_connection_id();

                    connections.lock().unwrap().insert(
                        connection.get_connection_id(),
                        Arc::new(Mutex::new(connection)),
                    );

                    connection_queue.push(connection_id);

                    continue;
                }

                // SERVER SENDING CONNECTION ACKNOWLEDGEMENT to CLIENT
                // Here we create the connection object on the client
                if packet.is_init() && packet.is_ack() {
                    let connection = Connection::new(
                        src,
                        socket.try_clone().unwrap(),
                        Some(packet.get_connection_id()),
                        Some(ConnectionCookie::from_bytes(packet.get_payload())),
                    );

                    connection.start_threads();

                    connections.lock().unwrap().insert(
                        connection.get_connection_id(),
                        Arc::new(Mutex::new(connection)),
                    );

                    continue;
                }

                // No new connection needs to be setup.
                // This means that the packet can be handled by the connection with the same
                // connection_id
                let connections = connections.lock().unwrap();
                let connection = connections.get(&packet.get_connection_id());
                let connection = match connection {
                    None => {
                        println!("We received data from a non existing connection. Ignoring");
                        continue;
                    }
                    Some(connection) => connection.clone(),
                };

                connection.lock().unwrap().receive_packet(packet);
            }
        });
    }

    pub fn accept(&self) -> Arc<Mutex<Connection>> {
        let connection_queue = Arc::clone(&self.connection_queue);

        loop {
            match connection_queue.lock().unwrap().pop() {
                Some(connection_id) => {
                    let mut connections = self.connections.lock().unwrap();

                    let connection = connections.get_mut(&connection_id).unwrap();

                    return connection.clone();
                }
                None => {}
            }
        }
    }

    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> Result<Arc<Mutex<Connection>>, Error> {
        // We want to initiate a new connection.
        // To do this, we need to send an init packet to the server

        let mut flags = PacketFlags::new(0);
        flags.init = true;

        let packet = Packet::new(PrimaryHeader::new(0, 0, 0, 0, flags), None, None, vec![]);

        let payload = packet.to_bytes();
        self.socket.send_to(&*payload, addr)?;

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
            return Ok(connection.clone());
        }

        Err(Error::new(std::io::ErrorKind::ConnectionRefused, "hello"))
    }
}
