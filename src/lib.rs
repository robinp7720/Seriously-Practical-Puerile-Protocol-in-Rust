mod connection;
mod connection_manager;
mod constants;
pub mod packet;

use crate::connection_manager::ConnectionManager;
use std::io::Error;
use std::net::SocketAddr;
use std::net::UdpSocket;

struct SPPPConnection {
    address: SocketAddr,
    connection_id: u64,
}

struct SPPPSocket {
    connection_manager: ConnectionManager,
    addr: SocketAddr,
}

impl SPPPSocket {
    pub fn new(addr: SocketAddr) -> Self {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();

        let connection_manager = connection_manager::ConnectionManager::new(socket);

        SPPPSocket {
            connection_manager,
            addr,
        }
    }

    pub fn accept(&self) -> Result<SPPPConnection, Error> {
        let connection_id = self.connection_manager.accept();

        Ok(SPPPConnection {
            address: self.addr,
            connection_id,
        })
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
