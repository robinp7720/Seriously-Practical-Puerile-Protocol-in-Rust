use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// TODO: Add MAC for security
#[derive(Debug)]
pub struct ConnectionCookie {
    pub timestamp: u128,
    pub lifetime: Duration,
    pub source_addr: SocketAddr,
    pub connection_id: u32,
}

impl ConnectionCookie {
    pub fn new(source_addr: SocketAddr, connection_id: u32) -> Self {
        ConnectionCookie {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            lifetime: Duration::from_secs(60),
            source_addr,
            connection_id,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();

        let timestamp: [u8; 16] = self.timestamp.to_be_bytes();
        let ip = match self.source_addr.ip() {
            IpAddr::V4(addr) => addr.octets(),
            IpAddr::V6(_addr) => {
                //TODO: Add IPv6 support to cookie
                //      Is it even possible? We don't know the length of the IP field in the cookie
                panic!("We don't support IPv6")
            }
        };
        let port = self.source_addr.port().to_be_bytes();
        let connection_id = self.connection_id.to_be_bytes();

        out.extend_from_slice(&timestamp);
        out.extend_from_slice(&ip);
        out.extend_from_slice(&port);
        out.extend_from_slice(&connection_id);

        out
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let timestamp: [u8; 16] = bytes[..16].try_into().unwrap();
        let source_ip: [u8; 4] = bytes[16..20].try_into().unwrap();
        let source_port = u16::from_be_bytes(bytes[20..22].try_into().unwrap());
        let connection_id: [u8; 4] = bytes[22..26].try_into().unwrap();

        let source_addr = SocketAddr::new(IpAddr::from(source_ip), source_port);

        ConnectionCookie {
            timestamp: u128::from_be_bytes(timestamp),
            lifetime: Duration::from_secs(60),
            source_addr,
            connection_id: u32::from_be_bytes(connection_id),
        }
    }

    pub fn has_expired(&self) -> bool {
        self.timestamp + self.lifetime.as_millis()
            > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
    }

    pub fn get_size(&self) -> usize {
        self.to_bytes().len()
    }
}
