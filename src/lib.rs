#![feature(hash_drain_filter)]
#![feature(map_try_insert)]
#[macro_use]
extern crate hex_literal;
extern crate lazy_static;

use std::io::Error;
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use connection::Connection;

use crate::connection::ConnectionState;
use crate::connection_manager::ConnectionManager;
use crate::connection_security::SecurityState;
use crate::constants::MAX_PAYLOAD_SIZE;
use crate::ConnectionState::CloseWait;

mod connection;
mod connection_manager;
mod connection_reliability_sender;
mod connection_security;
mod constants;
mod cookie;
mod packet;

/// SPPP Connection object handling one connection to a peer or server.
/// This object is returned to the program SPPPSocket::accept, SPPPSocket::listen.
pub struct SPPPConnection {
    connection: Arc<Mutex<Connection>>,
    receive_channel: Receiver<Vec<u8>>,
    receive_buffer: Vec<u8>,
}

impl SPPPConnection {
    /// Public API call to send data.
    ///
    /// # Arguments
    ///
    ///  *   `payload` - payload supposed to be send as a vector of bytes
    pub fn send(&self, payload: Vec<u8>) {
        while !self.can_send() {}

        let mut connection = self.connection.lock().unwrap();
        connection.send_data(payload);
    }

    pub fn can_send(&self) -> bool {
        self.connection.lock().unwrap().can_send()
    }

    /// Public API call to receive data.
    ///
    /// # Returns
    /// Returns a Result object containing a vector of payload bytes received or an error.
    pub fn recv(&mut self) -> Result<Vec<u8>, Error> {
        self.read_all_into_buffer();

        if self.receive_buffer.is_empty() {
            let data = self.receive_channel.recv().unwrap();
            let mut connection = self.connection.lock().unwrap();
            connection.reset_channel_buffer_size();
            return Ok(data);
        }
        let return_value = self.receive_buffer.clone();
        self.receive_buffer.clear();
        Ok(return_value)
    }

    fn read_all_into_buffer(&mut self) {
        while self.read_single_into_buffer() {}
        let mut connection = self.connection.lock().unwrap();
        connection.reset_channel_buffer_size();
        connection.update_external_buffer_size(self.receive_buffer.len());
    }

    fn read_single_into_buffer(&mut self) -> bool {
        match self.receive_channel.try_recv() {
            Ok(mut value) => {
                self.receive_buffer.append(&mut value);
                true
            }
            Err(_) => false,
        }
    }

    /// Public API call to check if data can be received.
    ///
    /// # Returns
    /// Returns True if data is in the receive buffer or false otherwise.
    pub fn can_recv(&mut self) -> bool {
        self.read_all_into_buffer();
        !self.receive_buffer.is_empty()
    }

    /// Private function call to wait while there are still unacknowledged packets.
    ///
    /// # Returns
    /// Returns True if data is in the receive buffer or false otherwise.
    pub fn wait_for_no_sending(&self) {
        // make private if not part of the api.
        while !self.connection.lock().unwrap().connection_can_close() {}
    }

    /// Public API call to check the corresponding connection to the SPPPConnection is closed.
    ///
    /// # Returns
    /// Returns True if connection is in the closed state or false otherwise.
    pub fn is_closed(&self) -> bool {
        self.connection.lock().unwrap().is_connection_closed()
    }

    pub fn wait_for_close(&self) {
        // !ToDo: Change API calls so that they match the description. This should probably be wait.
        while !self.is_closed() {}
        eprintln!("done here");
    }

    /// Public API call initiate the closing of the connection.
    pub fn close(&self) {
        eprintln!("Waiting for everything to be sent");
        self.wait_for_no_sending();

        {
            eprintln!("Send our intention to close the connection");
            self.connection.lock().unwrap().close();
        }

        eprintln!("We sent our intention to close. Wait for the connection to actually be closed");
        self.wait_for_close();

        eprintln!("Connection closed!");
    }

    pub fn client_closed(&self) -> bool {
        self.connection.lock().unwrap().get_connection_state() == CloseWait
    }
}

impl Drop for SPPPConnection {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct SPPPSocket {
    connection_manager: ConnectionManager,
    enable_encryption: bool,
}

impl SPPPSocket {
    /// Public API call to create a new SPPPSocket.
    /// This is the Object providing the functionality of the SPPProtocol.
    ///
    /// # Arguments
    ///
    /// *   `port` - port to connect the underlying UDP socket to.
    ///
    /// # Returns
    /// Returns the SPPPSocket object for the calling program to interact with.
    pub fn new(port: Option<u16>, enable_encryption: bool) -> Self {
        let socket = match port {
            None => UdpSocket::bind("0.0.0.0:0").unwrap(),
            Some(port) => UdpSocket::bind(format!("0.0.0.0:{}", port)).unwrap(),
        };

        eprintln!("{}", socket.local_addr().unwrap().port());

        let connection_manager =
            connection_manager::ConnectionManager::new(socket, enable_encryption);

        connection_manager.start();

        SPPPSocket {
            connection_manager,
            enable_encryption,
        }
    }

    /*pub fn listen(&self, queue_length: usize, whitelist: Option<Vec<IpAddr>>) -> Result<(), Error> {
        //self.connection_manager.listen(queue_length, whitelist)
        todo!()
    }*/

    /// Public API call to accept incoming connections and establish a connection.
    ///
    /// # Returns
    /// Returns the SPPPConnection object over which data can be sent and received.
    pub fn accept(&self) -> Result<SPPPConnection, Error> {
        let connection = self.connection_manager.accept();

        let receive_channel: Receiver<Vec<u8>> =
            { connection.lock().unwrap().get_receive_channel() };

        while connection.lock().unwrap().get_connection_state() != ConnectionState::Established {}

        if self.enable_encryption {
            eprintln!("Starting security");

            // wait till agree on algorithms is completed
            loop {
                {
                    if connection
                        .lock()
                        .unwrap()
                        .security
                        .algorithm_negotiation_finished()
                    {
                        break;
                    }
                }
                // TODO update this to a channel
                thread::sleep(Duration::from_millis(10));
            }

            eprintln!("Start DH");

            {
                connection.lock().unwrap().security.state = SecurityState::ExchangeKeys;
            }

            // wait till master secret is set
            loop {
                {
                    if connection.lock().unwrap().security.master_secret_set() {
                        break;
                    }
                }
                // TODO update this to a channel
                thread::sleep(Duration::from_millis(10));
            }
        }

        eprintln!("Connected");

        Ok(SPPPConnection {
            connection,
            receive_channel,
            receive_buffer: Vec::new(),
        })
    }

    /// Public API call to connect to another SPPPSocket.
    ///
    /// # Arguments
    ///
    /// *   `addr` - ToSocketAddrs object identifying the remote IP address and port.
    ///
    /// # Returns
    /// Returns the SPPPConnection object over which data can be sent and received.
    pub fn connect<A: ToSocketAddrs>(&mut self, addr: A) -> Result<SPPPConnection, Error> {
        let connection = self.connection_manager.connect(addr)?;

        let receive_channel: Receiver<Vec<u8>> =
            { connection.lock().unwrap().get_receive_channel() };

        eprintln!("Waiting for connection to be established");
        while connection.lock().unwrap().get_connection_state() != ConnectionState::Established {}

        if self.enable_encryption {
            eprintln!("Starting security");

            {
                // send packets for algorithm agreement and certificate exchange

                let mut connection = connection.lock().unwrap();
                let packets = connection.security.agree_on_algorithms_client();

                for mut packet in packets {
                    packet.set_connection_id(connection.get_connection_id());
                    connection.send_packet(packet);
                }
            }

            // wait till agree on algorithms is completed
            loop {
                {
                    if connection
                        .lock()
                        .unwrap()
                        .security
                        .algorithm_negotiation_finished()
                    {
                        break;
                    }
                }
                // TODO update this to a channel
                thread::sleep(Duration::from_millis(10));
            }

            eprintln!("Start DH");

            // wait till master secret is set
            loop {
                {
                    if connection.lock().unwrap().security.master_secret_set() {
                        break;
                    }
                }
                // TODO update this to a channel
                thread::sleep(Duration::from_millis(10));
            }
        }

        eprintln!("Connected");

        Ok(SPPPConnection {
            connection,
            receive_channel,
            receive_buffer: Vec::new(),
        })
    }
}

impl Drop for SPPPSocket {
    fn drop(&mut self) {
        eprintln!("SPPPPPPPP socket dropped");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
