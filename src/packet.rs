use std::io::Error;

#[derive(Debug)]
pub struct PrimaryHeader {
    connection_id: u32,
    seq_number: u32,
    ack_number: u32,
    arwnd: u16,
    flags: PacketFlags,
}

impl PrimaryHeader {
    pub(crate) fn new(
        connection_id: u32,
        seq_number: u32,
        ack_number: u32,
        arwnd: u16,
        flags: PacketFlags,
    ) -> PrimaryHeader {
        PrimaryHeader {
            connection_id,
            seq_number,
            ack_number,
            arwnd,
            flags,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.connection_id.to_be_bytes());
        bytes.extend_from_slice(&self.seq_number.to_be_bytes());
        bytes.extend_from_slice(&self.ack_number.to_be_bytes());
        bytes.extend_from_slice(&self.arwnd.to_be_bytes());
        bytes.extend_from_slice(&[self.flags.to_bytes()]);
        bytes.extend_from_slice(&[0 as u8]);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, &str> {
        if bytes.len() != 16 {
            return Err("header doesn't have a valid length");
        }

        let connection_id: u32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let seq_number: u32 = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let ack_number: u32 = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let arwnd: u16 = u16::from_be_bytes([bytes[12], bytes[13]]);
        let flags = PacketFlags::new(bytes[14]);
        let _next_header: u8 = bytes[15];

        Ok(PrimaryHeader::new(
            connection_id,
            seq_number,
            ack_number,
            arwnd,
            flags,
        ))
    }
}

#[derive(Debug)]
pub struct PacketFlags {
    pub init: bool,
    pub cookie: bool,
    pub ack: bool,
    pub fin: bool,
    pub reset: bool,
    pub sec: bool,
    pub arwnd_update: bool,
    pub reserved: bool,
}

impl PacketFlags {
    pub fn new(i: u8) -> Self {
        PacketFlags {
            init: i & 0b10000000 > 0,
            cookie: i & 0b01000000 > 0,
            ack: i & 0b00100000 > 0,
            fin: i & 0b00010000 > 0,
            reset: i & 0b00001000 > 0,
            sec: i & 0b00000100 > 0,
            arwnd_update: i & 0b00000010 > 0,
            reserved: i & 0b00000001 > 0,
        }
    }

    pub fn to_bytes(&self) -> u8 {
        let mut out = 0u8;

        if self.init {
            out += 1 << 7
        }
        if self.cookie {
            out += 1 << 6
        }
        if self.ack {
            out += 1 << 5
        }
        if self.fin {
            out += 1 << 4
        }
        if self.reset {
            out += 1 << 3
        }
        if self.sec {
            out += 1 << 2
        }
        if self.arwnd_update {
            out += 1 << 1
        }
        if self.reserved {
            out += 1 << 0
        }

        out
    }
}
#[derive(Debug)]
pub struct EncryptionHeader {
    pub number_supported_encryption: u8,
}

impl EncryptionHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        todo!();
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &str> {
        todo!();
    }
}

#[derive(Debug)]
pub struct SignatureHeader {
    pub length: u16,
    pub signature: Vec<u8>,
}

impl SignatureHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        todo!();
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &str> {
        todo!();
    }
}

#[derive(Debug)]
pub struct Packet {
    header: PrimaryHeader,
    encryption_header: Option<EncryptionHeader>,
    signature_header: Option<SignatureHeader>,
    payload: Vec<u8>,
}

impl Packet {
    pub fn new(
        header: PrimaryHeader,
        encryption_header: Option<EncryptionHeader>,
        signature_header: Option<SignatureHeader>,
        payload: Vec<u8>,
    ) -> Self {
        Packet {
            header,
            encryption_header,
            signature_header,
            payload,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.header.to_bytes());

        if let Some(encryption_header) = &self.encryption_header {
            out.extend_from_slice(&encryption_header.to_bytes());
        }

        if let Some(signature_header) = &self.signature_header {
            out.extend_from_slice(&signature_header.to_bytes());
        }

        out.extend_from_slice(&self.payload);
        out
    }

    pub fn get_connection_id(&self) -> u32 {
        self.header.connection_id
    }

    pub fn get_payload(&self) -> Vec<u8> {
        self.payload.to_vec()
    }

    pub fn payload_size(&self) -> usize {
        self.payload.to_vec().len()
    }

    pub fn get_sequence_number(&self) -> u32 {
        self.header.seq_number
    }

    pub fn set_sequence_number(&mut self, seq_num: u32) {
        self.header.seq_number = seq_num;
    }

    pub fn set_arwnd(&mut self, arwnd: u16) {
        self.header.arwnd = arwnd;
    }

    pub fn get_arwnd(&self) -> u16 {
        self.header.arwnd
    }

    pub fn get_ack_number(&self) -> u32 {
        self.header.ack_number
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &str> {
        if bytes.len() < 16 {
            return Err("Packet length is invalid");
        }

        let header = match PrimaryHeader::from_bytes(&bytes[..16]) {
            Ok(header) => header,
            Err(e) => return Err(e),
        };

        Ok(Packet {
            header,
            payload: bytes[16..].to_vec(),
            encryption_header: None,
            signature_header: None,
        })
    }

    pub fn is_init(&self) -> bool {
        self.header.flags.init
    }

    pub fn is_ack(&self) -> bool {
        self.header.flags.ack
    }

    pub fn is_cookie(&self) -> bool {
        self.header.flags.cookie
    }

    pub fn is_fin(&self) -> bool {
        self.header.flags.fin
    }

    pub fn is_arwnd(&self) -> bool {
        self.header.flags.arwnd_update
    }
}

#[cfg(test)]
mod packet {
    use crate::packet::{Packet, PacketFlags, PrimaryHeader};

    #[test]
    pub fn flag() {
        assert_eq!(PacketFlags::new(0b11111111).to_bytes(), 0b11111111);
    }

    #[test]
    pub fn test_from_bytes() {
        let data: Vec<u8> = vec![
            0u8, 0u8, 0u8, 1u8, 0u8, 0u8, 0u8, 2u8, 0u8, 0u8, 0u8, 3u8, 0u8, 4u8, 0b10110110, 0u8,
            'H' as u8, 'e' as u8, 'l' as u8, 'l' as u8, 'o' as u8, ' ' as u8, 'W' as u8, 'o' as u8,
            'r' as u8, 'l' as u8, 'd' as u8, '!' as u8,
        ];

        let packet = Packet::from_bytes(&data).unwrap();

        assert_eq!(packet.header.connection_id, 1u32);
        assert_eq!(packet.header.seq_number, 2u32);
        assert_eq!(packet.header.ack_number, 3u32);
        assert_eq!(packet.header.arwnd, 4u16);
        assert_eq!(packet.header.flags.init, true);
        assert_eq!(packet.header.flags.cookie, false);
        assert_eq!(packet.header.flags.ack, true);
        assert_eq!(packet.header.flags.fin, true);
        assert_eq!(packet.header.flags.reset, false);
        assert_eq!(packet.header.flags.arwnd_update, true);
        assert_eq!(packet.header.flags.sec, true);
        assert!(packet.signature_header.is_none());
        assert!(packet.encryption_header.is_none());
        assert_eq!(std::str::from_utf8(&*packet.payload), Ok("Hello World!"));
    }

    #[test]
    pub fn test_to_bytes() {
        let mut packet = Packet::new(
            PrimaryHeader {
                connection_id: 1u32,
                seq_number: 2u32,
                ack_number: 3u32,
                arwnd: 4u16,
                flags: PacketFlags {
                    init: true,
                    cookie: false,
                    ack: true,
                    fin: true,
                    reset: false,
                    sec: false,
                    arwnd_update: false,
                    reserved: false,
                },
            },
            None,
            None,
            "Hello World!".as_bytes().to_vec(),
        );

        assert_eq!(
            packet.to_bytes(),
            [
                0u8, 0u8, 0u8, 1u8, 0u8, 0u8, 0u8, 2u8, 0u8, 0u8, 0u8, 3u8, 0u8, 4u8, 0b10110000,
                0u8, 'H' as u8, 'e' as u8, 'l' as u8, 'l' as u8, 'o' as u8, ' ' as u8, 'W' as u8,
                'o' as u8, 'r' as u8, 'l' as u8, 'd' as u8, '!' as u8
            ]
        );
    }
}
