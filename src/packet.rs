use crate::connection_security::{EncryptionType, SignatureType};
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
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, &str> {
        if bytes.len() != 15 {
            // (next header not managed by this function)
            return Err("header doesn't have a valid length");
        }

        let connection_id: u32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let seq_number: u32 = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let ack_number: u32 = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let arwnd: u16 = u16::from_be_bytes([bytes[12], bytes[13]]);
        let flags = PacketFlags::new(bytes[14]);

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
    pub supported_encryption_algorithms: Vec<EncryptionType>,
    pub supported_signature_algorithms: Vec<SignatureType>,
}

impl EncryptionHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![];

        out.push(1); // next header
        out.push(self.supported_encryption_algorithms.len() as u8);
        out.push(self.supported_signature_algorithms.len() as u8);

        for algo in &self.supported_encryption_algorithms {
            out.push(match algo {
                EncryptionType::AES256counter => 1,
            });
        }

        for algo in &self.supported_signature_algorithms {
            out.push(match algo {
                SignatureType::SHA3_256 => 1,
            });
        }

        out
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let number_encryption = bytes[0];
        let number_signature = bytes[1];

        let mut header = EncryptionHeader {
            supported_signature_algorithms: vec![],
            supported_encryption_algorithms: vec![],
        };

        if number_encryption == 0 {
            return header;
        }
        for i in 2..number_encryption + 2 {
            match bytes[i as usize] {
                1 => header
                    .supported_encryption_algorithms
                    .push(EncryptionType::AES256counter),
                x => {
                    panic!("The encryption type {} is not known!", x)
                }
            }
        }

        for i in number_encryption + 1..bytes.len() as u8 {
            match bytes[i as usize] {
                1 => header
                    .supported_signature_algorithms
                    .push(SignatureType::SHA3_256),
                x => {
                    panic!("The signature type {} is not known!", x)
                }
            }
        }

        header
    }
}

#[derive(Debug)]
pub struct SignatureHeader {
    pub signature: Vec<u8>,
}

impl SignatureHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![];

        out.push(2);
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());

        out.extend_from_slice(&self.signature);

        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        SignatureHeader {
            signature: bytes[2..].to_vec(), // ignore the length field here
        }
    }

    pub fn new(signature: Vec<u8>) -> SignatureHeader {
        SignatureHeader { signature }
    }
}

#[derive(Debug)]
pub struct Packet {
    header: PrimaryHeader,
    pub encryption_header: Option<EncryptionHeader>,
    pub signature_header: Option<SignatureHeader>,
    payload: Vec<u8>,
    encrypted_payload: Option<Vec<u8>>,
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
            encrypted_payload: None,
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

        out.push(0); // next header

        out.extend_from_slice(&self.payload);
        out
    }

    pub fn get_connection_id(&self) -> u32 {
        self.header.connection_id
    }

    pub fn get_encrypted_payload(&self) -> Option<Vec<u8>> {
        match &self.encrypted_payload {
            None => None,
            Some(payload) => Some(payload.to_vec()),
        }
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

    pub fn get_signature(&self) -> Option<Vec<u8>> {
        match &self.signature_header {
            None => None,
            Some(header) => Some(header.signature.to_vec()),
        }
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

    pub fn set_encryption_header(&mut self, header: EncryptionHeader) {
        self.encryption_header = Some(header);
    }

    pub fn set_signature_header(&mut self, header: SignatureHeader) {
        self.signature_header = Some(header);
    }

    pub fn set_connection_id(&mut self, id: u32) {
        self.header.connection_id = id;
    }

    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    pub fn set_encrypted_payload(&mut self, payload: Option<Vec<u8>>) {
        self.encrypted_payload = payload;
    }

    pub fn push_encryption_to_payload(&mut self) {
        match &self.encrypted_payload {
            None => {}
            Some(payload) => self.payload = payload.to_vec(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &str> {
        if bytes.len() < 16 {
            return Err("Packet length is invalid");
        }

        let header = match PrimaryHeader::from_bytes(&bytes[..15]) {
            Ok(header) => header,
            Err(e) => return Err(e),
        };

        let mut encryption_header: Option<EncryptionHeader> = None;
        let mut signature_header: Option<SignatureHeader> = None;

        let mut next_header_index = 15;
        while bytes[next_header_index] != 0 {
            match bytes[next_header_index] {
                1 => {
                    // calculate encryption header length
                    let length = (bytes[next_header_index + 1] as u16
                        + bytes[next_header_index + 2] as u16)
                        as usize;

                    encryption_header = Some(EncryptionHeader::from_bytes(
                        &bytes[next_header_index + 1..next_header_index + 1 + 2 + length],
                    ));

                    // update the next header field
                    next_header_index += 2 + length + 1;
                }
                2 => {
                    // calculate signature header length
                    let length = u16::from_be_bytes([
                        bytes[next_header_index + 1],
                        bytes[next_header_index + 2],
                    ]) as usize;

                    signature_header = Some(SignatureHeader::from_bytes(
                        &bytes[next_header_index + 1..next_header_index + 1 + 2 + length],
                    ));

                    // update the next header field
                    next_header_index += 2 + length + 1;
                }
                _ => return Err("This next header id is reserved!"),
            }
        }

        Ok(Packet {
            header,
            payload: bytes[next_header_index + 1..].to_vec(),
            encryption_header,
            signature_header,
            encrypted_payload: None,
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

    pub fn is_sec(&self) -> bool {
        self.header.flags.sec
    }

    pub fn set_sec(&mut self, sec: bool) {
        self.header.flags.sec = sec;
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
