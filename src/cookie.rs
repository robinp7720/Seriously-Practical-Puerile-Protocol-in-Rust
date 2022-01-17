use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha3::Sha3_256;

use crate::constants::CONNECTION_COOKIE_HMAC_KEY;

#[derive(Debug)]
pub struct ConnectionCookie {
    pub timestamp: u128,
    pub lifetime: Duration,
    pub source_addr: SocketAddr,
    pub connection_id: u32,
    pub hmac: Option<Vec<u8>>,
}

impl ConnectionCookie {
    // creates a new cookie from the passed parameters and calculate the hmac
    pub fn new(source_addr: SocketAddr, connection_id: u32) -> Self {
        let cookie = ConnectionCookie {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            lifetime: Duration::from_secs(60),
            source_addr,
            connection_id,
            hmac: None,
        };

        cookie.calculate_hmac()
    }

    // consumes the ConnectionCookie; calculates the hmac of it and retuns the cookie with the hmac set
    pub fn calculate_hmac(mut self) -> ConnectionCookie {
        type HmacSha256 = Hmac<Sha3_256>;

        let mut mac = HmacSha256::new_from_slice(CONNECTION_COOKIE_HMAC_KEY.as_bytes())
            .expect("HMAC can take key of any size");

        mac.update(&self.to_bytes(false));

        let result = mac.finalize();
        let vec = result.into_bytes()[..].to_vec();

        self.hmac = Some(vec);

        self
    }

    /// Formats the cookie with the following structure:
    /// - 16 bytes timestamp in millis
    /// - 2 bytes port number
    //  - 4 bytes connection id
    /// - 32 bytes HMAC
    /// - 1 byte ip version (either 4 or 6)
    /// - 4/16 bytes ip content (depending on ip version)
    pub fn to_bytes(&self, include_hmac: bool) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();

        let timestamp: [u8; 16] = self.timestamp.to_be_bytes();
        let ip = match self.source_addr.ip() {
            IpAddr::V4(addr) => (4u8, addr.octets().to_vec()),
            IpAddr::V6(addr) => (6u8, addr.octets().to_vec()),
        };
        let port = self.source_addr.port().to_be_bytes();
        let connection_id = self.connection_id.to_be_bytes();

        out.extend_from_slice(&timestamp);
        out.extend_from_slice(&port);
        out.extend_from_slice(&connection_id);

        if include_hmac {
            let hmac: [u8; 32] = self.hmac.as_ref().unwrap()[0..32].try_into().unwrap();
            out.extend_from_slice(&hmac);
        }

        out.push(ip.0);
        out.extend_from_slice(&ip.1);

        out
    }

    // basically reverses the "to_bytes" operation
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let timestamp: [u8; 16] = bytes[..16].try_into().unwrap();
        let source_port = u16::from_be_bytes(bytes[16..18].try_into().unwrap());
        let connection_id: [u8; 4] = bytes[18..22].try_into().unwrap();
        let hmac = bytes[22..(22 + 32)].to_vec();
        let ip_version = bytes[54];
        let ip = if ip_version == 4 {
            let octets: [u8; 4] = bytes[55..(55 + 4)].try_into().unwrap();
            IpAddr::from(octets)
        } else {
            let octets: [u8; 16] = bytes[55..(55 + 16)].try_into().unwrap();
            IpAddr::from(octets)
        };

        let source_addr = SocketAddr::new(ip, source_port);

        ConnectionCookie {
            timestamp: u128::from_be_bytes(timestamp),
            lifetime: Duration::from_secs(60),
            source_addr,
            connection_id: u32::from_be_bytes(connection_id),
            hmac: Some(hmac),
        }
    }

    // checks weather the cookie has expired
    pub fn has_expired(&self) -> bool {
        self.timestamp + self.lifetime.as_millis()
            < SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
    }
}
