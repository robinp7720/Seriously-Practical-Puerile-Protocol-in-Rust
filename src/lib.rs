#![feature(hash_drain_filter)]

mod connection;
mod connection_manager;
mod constants;
mod cookie;
mod packet;

use connection::Connection;

use crate::connection::ConnectionState;
use crate::connection_manager::ConnectionManager;
use std::io::Error;
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};

/// SPPP Connection object handling one connection to a peer or server.
/// This object is returned to the program SPPPSocket::accept, SPPPSocket::listen.
#[derive(Clone)]
pub struct SPPPConnection {
    connection: Arc<Mutex<Connection>>,
}

impl SPPPConnection {
    /// Public API call to send data.
    ///
    /// # Arguments
    ///
    ///  *   `payload` - payload supposed to be send as a vector of bytes
    pub fn send(&self, payload: Vec<u8>) {
        let mut connection = self.connection.lock().unwrap();
        connection.send_data(payload);
    }

    /// Public API call to receive data.
    ///
    /// # Returns
    /// Returns a Result object containing a vector of payload bytes received or an error.
    pub fn recv(&mut self) -> Result<Vec<u8>, Error> {
        while !self.can_recv() {}

        Ok(self.connection.lock().unwrap().recv())
    }

    /// Public API call to check if data can be received.
    ///
    /// # Returns
    /// Returns True if data is in the receive buffer or false otherwise.
    pub fn can_recv(&self) -> bool {
        self.connection.lock().unwrap().can_recv()
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
        println!("done here");
    }

    /// Public API call initiate the closing of the connection.
    pub fn close(&self) {
        println!("Waiting for everything to be sent");
        self.wait_for_no_sending();

        {
            println!("Send our intention to close the connection");
            self.connection.lock().unwrap().close();
        }

        println!("We sent our intention to close. Wait for the connection to actually be closed");
        self.wait_for_close();

        println!("Connection closed!");
    }
}

impl Drop for SPPPConnection {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct SPPPSocket {
    connection_manager: ConnectionManager,
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
    pub fn new(port: Option<u16>) -> Self {
        let socket = match port {
            None => UdpSocket::bind("0.0.0.0:0").unwrap(),
            Some(port) => UdpSocket::bind(format!("0.0.0.0:{}", port)).unwrap(),
        };

        println!("{}", socket.local_addr().unwrap().port());

        let connection_manager = connection_manager::ConnectionManager::new(socket);

        connection_manager.start();

        SPPPSocket { connection_manager }
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

        while connection.lock().unwrap().get_connection_state() != ConnectionState::Established {}

        Ok(SPPPConnection { connection })
    }

    /// Public API call to connect to another SPPPSocket.
    ///
    /// # Arguments
    ///
    /// *   `addr` - ToSocketAddrs object identifying the remote IP address and port.
    ///
    /// # Returns
    /// Returns the SPPPConnection object over which data can be sent and received.
    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> Result<SPPPConnection, Error> {
        let connection = self.connection_manager.connect(addr)?;

        {
            connection.lock().unwrap().send_cookie_echo();
        }

        println!("Waiting for connection to be established");
        while connection.lock().unwrap().get_connection_state() != ConnectionState::Established {}

        Ok(SPPPConnection { connection })
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
