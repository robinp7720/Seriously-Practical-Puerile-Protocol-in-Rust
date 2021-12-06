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

    fn from_bytes(bytes: &[u8]) -> PrimaryHeader {
        let connection_id: u32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let seq_number: u32 = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let ack_number: u32 = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let arwnd: u16 = u16::from_be_bytes([bytes[12], bytes[13]]);
        let flags = PacketFlags::new(bytes[14]);
        let next_header: u8 = bytes[15];

        PrimaryHeader::new(connection_id, seq_number, ack_number, arwnd, flags)
    }
}

#[derive(Debug)]
pub struct PacketFlags {
    pub init: bool,
    pub cookie: bool,
    pub ack: bool,
    pub fin: bool,
    pub reset: bool,
}

impl PacketFlags {
    pub fn new(i: u8) -> Self {
        PacketFlags {
            init: i & 0b10000000 > 0,
            cookie: i & 0b01000000 > 0,
            ack: i & 0b00100000 > 0,
            fin: i & 0b00010000 > 0,
            reset: i & 0b00001000 > 0,
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
    pub fn from_bytes(bytes: &[u8]) -> Self {
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
    pub fn from_bytes(bytes: &[u8]) -> Self {
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

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Packet {
            header: PrimaryHeader::from_bytes(&*bytes),
            payload: bytes[16..].to_vec(),
            encryption_header: None,
            signature_header: None,
        }
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
}
