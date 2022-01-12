use crate::connection_security::SignatureType::SHA3_256;
use crate::constants::{DIFFIE_HELLMAN_GENERATOR, DIFFIE_HELLMAN_PRIME};
use crate::packet::{EncryptionHeader, Packet, PacketFlags, PrimaryHeader, SignatureHeader};
use crate::{Connection, SPPPConnection, MAX_PAYLOAD_SIZE};
use aes::cipher::generic_array::{typenum::U32, GenericArray};
use aes::cipher::{NewCipher, StreamCipher};
use aes::{Aes192Ctr, Aes256Ctr, Block};
use cipher::generic_array::arr;
use cipher::{SeekNum, StreamCipherSeek};
use hkdf::Hkdf;
use hmac::digest::MacError;
use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer, Verifier};
use openssl::x509::{X509VerifyResult, X509};
use rand::rngs::OsRng;
use sha3::Sha3_256;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;
use std::{fs, io};

#[derive(Debug)]
pub struct Security {
    encryption_type: Option<EncryptionType>,
    signature_type: Option<SignatureType>,
    other_certificate: Option<X509>,
    other_recieved_certificate_bytes: Vec<u8>,
    pub state: SecurityState,
    master_secret: Option<BigInt>,
    dh_private_key: Option<BigInt>,
    dh_own_public_key: Option<BigInt>,
    dh_other_public_key: Option<BigInt>,
    key_payload_to_server: Option<BigInt>,
    key_payload_to_client: Option<BigInt>,
    key_hmac_to_server: Option<BigInt>,
    key_hmac_to_client: Option<BigInt>,
    key_initial_vector: Option<BigInt>,
    aes_key_stream_encrypt: Option<Aes256Ctr>,
    aes_key_stream_decrypt: Option<Aes256Ctr>,
}

lazy_static! {
    static ref CERTIFICATE_AITHORITYS: Vec<X509> = {
        let mut certs: Vec<X509> = Vec::new();

        for file in fs::read_dir("./certificates/CA").unwrap() {
            let path = file.unwrap().path();

            let content = fs::read_to_string(path).unwrap();

            let certificate = X509::from_pem(content.as_bytes()).unwrap();
            certs.push(certificate);
        }

        certs
    };
    static ref CETIFICATE: X509 = {
        let content = fs::read_to_string(Path::new("./certificates/server.crt")).unwrap();
        X509::from_pem(content.as_bytes()).unwrap()
    };
    static ref RSA_PRIVATE_KEY: PKey<Private> = {
        let content = fs::read_to_string(Path::new("./certificates/server.key")).unwrap();
        let key = PKey::<Private>::private_key_from_pem(content.as_bytes()).unwrap();
        key
    };
}
impl Security {
    pub fn new() -> Security {
        Security {
            encryption_type: None,
            signature_type: None,
            other_certificate: None,
            other_recieved_certificate_bytes: vec![],
            state: SecurityState::ExchangeAlgorithms,
            master_secret: None,
            dh_private_key: None,
            dh_own_public_key: None,
            dh_other_public_key: None,
            key_payload_to_server: None,
            key_payload_to_client: None,
            key_hmac_to_server: None,
            key_hmac_to_client: None,
            key_initial_vector: None,
            aes_key_stream_encrypt: None,
            aes_key_stream_decrypt: None,
        }
    }

    pub fn check_certificate(&mut self, payload: Vec<u8>) -> Result<(), &'static str> {
        self.other_recieved_certificate_bytes
            .extend_from_slice(&payload);

        let payload = String::from_utf8(self.other_recieved_certificate_bytes.to_vec()).unwrap();
        let cert = match X509::from_pem(payload.as_bytes()) {
            Ok(cert) => cert,
            Err(_) => return Err("Could not parse yet!"),
        };

        self.other_recieved_certificate_bytes.clear();

        self.other_certificate = Some(cert);
        let cert = self.other_certificate.as_ref().unwrap();

        // check if one of the CA is issuing the received one
        for ca in CERTIFICATE_AITHORITYS.iter() {
            match cert.verify(&ca.public_key().unwrap()).unwrap() {
                true => return Ok(()),
                false => {}
            }
        }

        Err("Can not find issuing certificate!")
    }

    pub fn agree_on_algorithms_client(&self) -> Vec<Packet> {
        let payload = CETIFICATE.to_pem().unwrap();

        let chunks: Vec<&[u8]> = payload.chunks(MAX_PAYLOAD_SIZE).collect();

        let mut packets = Vec::new();

        for chunk in chunks {
            let mut flags = PacketFlags::new(0);
            flags.sec = true;

            let header = PrimaryHeader::new(0, 0, 0, 0, flags);
            let encryption_header = EncryptionHeader {
                supported_encryption_algorithms: vec![EncryptionType::AES256counter],
                supported_signature_algorithms: vec![SignatureType::SHA3_256],
            };

            let packet = Packet::new(header, Some(encryption_header), None, chunk.to_vec());
            packets.push(packet);
        }

        packets
    }

    pub fn agree_on_algorithms_server(
        &mut self,
        header: &EncryptionHeader,
    ) -> Result<Vec<Packet>, (Vec<Packet>, &'static str)> {
        // The own certificate should be the payload
        let payload = CETIFICATE.to_pem().unwrap();

        // split the certificate into multiple parts when it exeeds the max payload
        let chunks: Vec<&[u8]> = payload.chunks(MAX_PAYLOAD_SIZE).collect();

        let mut enc_algo = None;
        let mut sig_algo = None;

        if header
            .supported_encryption_algorithms
            .contains(&EncryptionType::AES256counter)
        {
            enc_algo = Some(EncryptionType::AES256counter);
        }

        if header
            .supported_signature_algorithms
            .contains(&SignatureType::SHA3_256)
        {
            sig_algo = Some(SignatureType::SHA3_256);
        }

        let mut packets = Vec::new();

        // there is no common algorithms between the parties
        if !enc_algo.is_some() || !sig_algo.is_some() {
            eprintln!("Could not agree on algos!");

            let mut flags = PacketFlags::new(0);
            flags.sec = true;

            let primary_header = PrimaryHeader::new(0, 0, 0, 0, flags);

            let encryption_header = EncryptionHeader {
                supported_encryption_algorithms: vec![],
                supported_signature_algorithms: vec![],
            };

            let packet = Packet::new(primary_header, Some(encryption_header), None, vec![]);

            packets.push(packet);

            return Err((packets, "Could not agree on algorithms!"));
        }

        for chunk in chunks {
            let mut flags = PacketFlags::new(0);
            flags.sec = true;

            let primary_header = PrimaryHeader::new(0, 0, 0, 0, flags);

            let encryption_header = EncryptionHeader {
                supported_encryption_algorithms: vec![enc_algo.clone().unwrap()],
                supported_signature_algorithms: vec![sig_algo.clone().unwrap()],
            };

            let packet = Packet::new(
                primary_header,
                Some(encryption_header),
                None,
                chunk.to_vec(),
            );

            packets.push(packet);
        }

        self.set_algorithms(enc_algo.unwrap(), sig_algo.unwrap());

        Ok(packets)
    }

    pub fn set_algorithms(&mut self, enc: EncryptionType, sig: SignatureType) {
        eprintln!(
            "Agreed on algorithms. Encryption: {:?}, Signature: {:?}",
            enc, sig
        );
        self.encryption_type = Some(enc);
        self.signature_type = Some(sig);
    }

    pub fn algos_set(&self) -> bool {
        self.encryption_type.is_some() && self.signature_type.is_some()
    }

    fn rsa_sign(&self, payload: Vec<u8>, is_client: bool) -> Vec<u8> {
        match self.signature_type.unwrap() {
            SHA3_256 => {
                let mut signer = Signer::new(MessageDigest::sha3_256(), &RSA_PRIVATE_KEY).unwrap();
                signer.update(&payload).unwrap();

                signer.sign_to_vec().unwrap()
            }
        }
    }

    pub fn rsa_verify_signature(&self, payload: Vec<u8>, received_signature: Vec<u8>) {
        let other_certificate = self.other_certificate.as_ref().unwrap();
        let public_key = other_certificate.public_key().unwrap();

        match self.signature_type.unwrap() {
            SHA3_256 => {
                let mut verifier = Verifier::new(MessageDigest::sha3_256(), &public_key).unwrap();
                verifier.update(&payload).unwrap();

                match verifier.verify(&received_signature).unwrap() {
                    true => return,
                    false => panic!("The signature did not match!"),
                }
            }
        }
    }

    pub fn start_exchange_keys_client(&mut self) -> Packet {
        let generator = DIFFIE_HELLMAN_GENERATOR;
        let prime = BigInt::from_bytes_be(Sign::Plus, &DIFFIE_HELLMAN_PRIME);

        // generate private_key (This key needs to be secret!)
        let mut rng = rand::thread_rng();

        // generate private key (This key needs to be kept secret!)
        self.dh_private_key = Some(rng.gen_bigint_range(&BigInt::from(0_i32), &prime));

        // public key = (generator ^ private_key) mod prime
        self.dh_own_public_key =
            Some(BigInt::from(generator).modpow(&self.dh_private_key.as_ref().unwrap(), &prime));

        let mut payload = Vec::new();

        let public_key_bytes = self.dh_own_public_key.as_ref().unwrap().to_bytes_be().1;
        let prime_as_bytes = prime.to_bytes_be().1;

        // push length fields
        payload.extend_from_slice(&(public_key_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(&(generator.to_be_bytes().len() as u16).to_be_bytes());
        payload.extend_from_slice(&(prime_as_bytes.len() as u16).to_be_bytes());

        // push content
        payload.extend_from_slice(&public_key_bytes);
        payload.extend_from_slice(&generator.to_be_bytes());
        payload.extend_from_slice(&prime_as_bytes);

        let signature_header = self.rsa_sign(payload.to_vec(), true);
        let signature_header = SignatureHeader::new(signature_header);

        let mut flags = PacketFlags::new(0);
        flags.sec = true;

        let header = PrimaryHeader::new(0, 0, 0, 0, flags);

        Packet::new(header, None, Some(signature_header), payload)
    }

    pub fn end_exchange_keys_client(&mut self, payload: Vec<u8>) {
        let prime = BigInt::from_bytes_be(Sign::Plus, &DIFFIE_HELLMAN_PRIME);

        let other_key_length = u16::from_be_bytes([payload[0], payload[1]]);

        self.dh_other_public_key = Some(BigInt::from_bytes_be(
            Sign::Plus,
            &payload[2..(other_key_length + 2) as usize],
        ));

        self.master_secret = Some(
            self.dh_other_public_key
                .as_ref()
                .unwrap()
                .modpow(&self.dh_private_key.as_ref().unwrap(), &prime),
        );

        self.derive_keys();
    }

    pub fn exchange_keys_server(&mut self, payload: Vec<u8>) -> Packet {
        let generator = DIFFIE_HELLMAN_GENERATOR;
        let prime = BigInt::from_bytes_be(Sign::Plus, &DIFFIE_HELLMAN_PRIME);

        // generate private_key (This key needs to be secret!)
        let mut rng = rand::thread_rng();

        // generate private key (This key needs to be kept secret!)
        self.dh_private_key = Some(rng.gen_bigint_range(&BigInt::from(0_i32), &prime));

        // public key = (generator ^ private_key) mod prime
        self.dh_own_public_key =
            Some(BigInt::from(generator).modpow(&self.dh_private_key.as_ref().unwrap(), &prime));

        let other_key_length = u16::from_be_bytes([payload[0], payload[1]]);
        let generator_length = u16::from_be_bytes([payload[2], payload[3]]);
        let prime_length = u16::from_be_bytes([payload[4], payload[5]]);

        self.dh_other_public_key = Some(BigInt::from_bytes_be(
            Sign::Plus,
            &payload[6..(other_key_length + 6) as usize],
        ));

        self.master_secret = Some(
            self.dh_other_public_key
                .as_ref()
                .unwrap()
                .modpow(&self.dh_private_key.as_ref().unwrap(), &prime),
        );

        self.derive_keys();

        let mut payload = Vec::new();

        let public_key_bytes = self.dh_own_public_key.as_ref().unwrap().to_bytes_be().1;

        // push length fields
        payload.extend_from_slice(&(public_key_bytes.len() as u16).to_be_bytes());

        // push content
        payload.extend_from_slice(&public_key_bytes);

        // sign the DH packet with RSA private key
        let signature = self.rsa_sign(payload.to_vec(), false);
        let signature_header = SignatureHeader::new(signature);

        let mut flags = PacketFlags::new(0);
        flags.sec = true;

        let header = PrimaryHeader::new(0, 0, 0, 0, flags);

        Packet::new(header, None, Some(signature_header), payload)
    }

    pub fn master_secret_set(&self) -> bool {
        self.master_secret.is_some()
    }

    pub fn derive_keys(&mut self) {
        match self.signature_type.unwrap() {
            SignatureType::SHA3_256 => {
                let hk = Hkdf::<Sha3_256>::new(
                    None,
                    &self.master_secret.as_ref().unwrap().to_bytes_be().1,
                );

                // buffer for the generated keys
                let mut okm = match self.encryption_type.unwrap() {
                    EncryptionType::AES256counter => [0u8; 32],
                };

                // KEY 1
                hk.expand("payload-client-to-server".as_bytes(), &mut okm)
                    .expect("HKDF supports 32bit keys");
                self.key_payload_to_server = Some(BigInt::from_bytes_be(Sign::Plus, &okm));

                // KEY 2
                hk.expand("payload-server-to-client".as_bytes(), &mut okm)
                    .expect("HKDF supports 32bit keys");
                self.key_payload_to_client = Some(BigInt::from_bytes_be(Sign::Plus, &okm));

                // KEY 3
                hk.expand("hmac-client-to-server".as_bytes(), &mut okm)
                    .expect("HKDF supports 32bit keys");
                self.key_hmac_to_server = Some(BigInt::from_bytes_be(Sign::Plus, &okm));

                // KEY 4
                hk.expand("hmac-server-to-client".as_bytes(), &mut okm)
                    .expect("HKDF supports 32bit keys");
                self.key_hmac_to_client = Some(BigInt::from_bytes_be(Sign::Plus, &okm));

                let mut okm = match self.encryption_type.unwrap() {
                    EncryptionType::AES256counter => [0u8; 16],
                };

                // KEY 5
                hk.expand("IV".as_bytes(), &mut okm)
                    .expect("HKDF supports 32bit keys");
                self.key_initial_vector = Some(BigInt::from_bytes_be(Sign::Plus, &okm));
            }
        }
    }

    pub fn encrypt_bytes(&mut self, bytes: Vec<u8>, is_client: bool) -> (Vec<u8>, Vec<u8>) {
        let mut bytes = bytes;

        if self.encryption_type.is_none() || self.master_secret.is_none() || bytes.len() == 0 {
            return (bytes, vec![]);
        }

        let server_key = self.key_payload_to_server.as_ref().unwrap().to_bytes_be().1;
        let client_key = self.key_payload_to_client.as_ref().unwrap().to_bytes_be().1;

        let key = match is_client {
            true => client_key,
            false => server_key,
        };

        let iv_key = self.key_initial_vector.as_ref().unwrap().to_bytes_be().1;

        match self.encryption_type.unwrap() {
            EncryptionType::AES256counter => {
                match &self.aes_key_stream_encrypt {
                    Some(_) => {}
                    None => {
                        self.aes_key_stream_encrypt =
                            Some(Aes256Ctr::new_from_slices(&key, &iv_key).unwrap())
                    }
                };

                match &mut self.aes_key_stream_encrypt {
                    None => {
                        panic!("This case is not possible!")
                    }
                    Some(aes) => {
                        aes.apply_keystream(&mut bytes);
                    }
                };
            }
        }

        let valid_signature = self.sign_packet(bytes.to_vec(), is_client);

        (bytes, valid_signature)
    }

    pub fn decrypt_bytes(
        &mut self,
        bytes: Vec<u8>,
        signature: Vec<u8>,
        is_client: bool,
    ) -> Result<Vec<u8>, &str> {
        let mut bytes = bytes;

        if self.encryption_type.is_none() || self.master_secret.is_none() || bytes.len() == 0 {
            return Ok(bytes);
        }

        if !self.verify_signature(bytes.to_vec(), signature, is_client) {
            return Err(
                "Signature is not matching. Therefore it is possible that the message was altered!",
            );
        }

        let server_key = self.key_payload_to_server.as_ref().unwrap().to_bytes_be().1;
        let client_key = self.key_payload_to_client.as_ref().unwrap().to_bytes_be().1;

        let key = match is_client {
            true => server_key,
            false => client_key,
        };

        let iv_key = self.key_initial_vector.as_ref().unwrap().to_bytes_be().1;

        match self.encryption_type.unwrap() {
            EncryptionType::AES256counter => {
                match &self.aes_key_stream_decrypt {
                    Some(_) => {}
                    None => {
                        self.aes_key_stream_decrypt =
                            Some(Aes256Ctr::new_from_slices(&key, &iv_key).unwrap())
                    }
                };

                match &mut self.aes_key_stream_decrypt {
                    None => {
                        panic!("This case is not possible!")
                    }
                    Some(aes) => {
                        aes.apply_keystream(&mut bytes);
                    }
                };
            }
        }

        Ok(bytes)
    }

    fn sign_packet(&self, bytes: Vec<u8>, is_client: bool) -> Vec<u8> {
        let server_key = self.key_hmac_to_server.as_ref().unwrap().to_bytes_be().1;
        let client_key = self.key_hmac_to_client.as_ref().unwrap().to_bytes_be().1;

        let key = match is_client {
            true => server_key,
            false => client_key,
        };

        match self.signature_type.unwrap() {
            SignatureType::SHA3_256 => {
                // Create alias for HMAC-SHA256
                type HmacSha256 = Hmac<Sha3_256>;

                let mut mac =
                    HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
                mac.update(&bytes);

                let result = mac.finalize();
                result.into_bytes()[..].to_vec()
            }
        }
    }

    fn verify_signature(&self, bytes: Vec<u8>, signature: Vec<u8>, is_client: bool) -> bool {
        let server_key = self.key_hmac_to_server.as_ref().unwrap().to_bytes_be().1;
        let client_key = self.key_hmac_to_client.as_ref().unwrap().to_bytes_be().1;

        let key = match is_client {
            true => client_key,
            false => server_key,
        };

        match self.signature_type.unwrap() {
            SignatureType::SHA3_256 => {
                type HmacSha256 = Hmac<Sha3_256>;

                let mut mac =
                    HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");

                mac.update(&bytes);

                match mac.verify_slice(&signature[..]) {
                    Ok(_) => true,
                    Err(_) => false,
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum EncryptionType {
    AES256counter, // ID: 1
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SignatureType {
    SHA3_256, // ID: 1
}

#[derive(Debug, PartialEq)]
pub enum SecurityState {
    ExchangeAlgorithms,
    ExchangeKeys,
    Secured,
}
