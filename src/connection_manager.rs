use std::collections::HashMap;
use std::io::Error;
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

use crate::connection::Connection;
use crate::constants::MAX_PACKET_SIZE;
use crate::packet::Packet;
use crate::ConnectionState;

pub struct ConnectionManager {
    connections: Arc<Mutex<HashMap<u32, Arc<Mutex<Connection>>>>>,
    connection_queue: Arc<Mutex<Vec<u32>>>,
    socket: UdpSocket,
    encryption_enabled: bool,
}

impl ConnectionManager {
    pub fn new(socket: UdpSocket, encryption_enabled: bool) -> Self {
        ConnectionManager {
            socket,
            connections: Arc::new(Mutex::new(HashMap::new())),
            connection_queue: Arc::new(Mutex::new(Vec::new())),
            encryption_enabled,
        }
    }

    pub fn start(&self) {
        self.start_recv_thread();
    }

    fn start_recv_thread(&self) {
        let socket = self.socket.try_clone().unwrap();

        let connection_queue = Arc::clone(&self.connection_queue);
        let connections = Arc::clone(&self.connections);

        let encryption_enabled = self.encryption_enabled;

        // Listening thread
        thread::spawn(move || loop {
            let mut buf = [0; MAX_PACKET_SIZE];

            loop {
                let (amt, src) = socket.recv_from(&mut buf).unwrap();

                let packet = match Packet::from_bytes(&buf[..amt]) {
                    Ok(packet) => packet,
                    Err(_) => {
                        eprintln!("Received a packet which couldn't be parsed");
                        continue;
                    }
                };

                // CLIENT SENDING A CONNECTION REQUEST TO SERVER
                // Here we create the connection object for the server
                // If the connection id is 0, it means that we are receiving a new connection
                // request.
                // Therefore, we need to add the new connection request to the connection queue.
                if packet.get_connection_id() == 0 && packet.is_init() {
                    let connection_id: u32 = rand::random();

                    let mut connection = Connection::new(
                        src,
                        socket.try_clone().unwrap(),
                        connection_id,
                        false,
                        encryption_enabled,
                    );

                    connection.send_init_ack();

                    connections
                        .lock()
                        .unwrap()
                        .insert(connection_id, Arc::new(Mutex::new(connection)));

                    continue;
                }

                // Push the connection into the available connections queue when the connection
                // is actually in a state where the connection id is known.
                if packet.is_cookie() && !packet.is_ack() {
                    let connection_lock = connections.lock().unwrap();

                    let connection = connection_lock.get(&packet.get_connection_id()).unwrap();

                    if connection.lock().unwrap().get_connection_state() == ConnectionState::Listen
                    {
                        let mut connection_queue = connection_queue.lock().unwrap();
                        connection_queue.push(packet.get_connection_id());
                    }
                }

                // SERVER SENDING CONNECTION ACKNOWLEDGEMENT to CLIENT
                // Here we create the connection object on the client
                if packet.is_init() && packet.is_ack() {
                    let connection = match connections.lock().unwrap().remove(&0) {
                        None => {
                            eprintln!("We received an init ack but we don't have a connection waiting to be setup!");
                            continue;
                        }
                        Some(connection) => connection,
                    };

                    connection
                        .lock()
                        .unwrap()
                        .set_connection_id(packet.get_connection_id());

                    match connections
                        .lock()
                        .unwrap()
                        .try_insert(packet.get_connection_id(), connection)
                    {
                        Ok(_) => {
                            eprintln!("connection inserted into hashmap")
                        }
                        Err(e) => {
                            eprintln!("Connection with same id already exists! The cookie echo was probably lost. We need to resend it. Letting the socket retransmission handle it");
                        }
                    }

                    // Fall through to the packet handling
                    // We want the actual packet to be sent to connection for processing
                }

                // No new connection needs to be setup.
                // This means that the packet can be handled by the connection with the same
                // connection_id
                let connections = connections.lock().unwrap();
                let connection = connections.get(&packet.get_connection_id());
                match connection {
                    None => {
                        eprintln!("We received data from a non existing connection. Ignoring");
                        continue;
                    }
                    Some(connection) => {
                        connection.lock().unwrap().receive_packet(packet);
                    }
                };
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

                    let cloned_connection = Arc::clone(&connection);

                    return cloned_connection;
                }
                None => {}
            }
        }
    }

    pub fn connect<A: ToSocketAddrs>(&mut self, addr: A) -> Result<Arc<Mutex<Connection>>, Error> {
        // We want to initiate a new connection.
        // To do this, we need to send an init packet to the server

        let connection = Arc::new(Mutex::new(Connection::new(
            addr.to_socket_addrs().unwrap().next().unwrap(),
            self.socket.try_clone().unwrap(),
            0,
            true,
            self.encryption_enabled,
        )));

        self.connections
            .lock()
            .unwrap()
            .insert(0, connection.clone());

        {
            connection.lock().unwrap().send_init();
        };

        return Ok(connection.clone());
    }
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        eprintln!("Connection manager dropped");
    }
}
