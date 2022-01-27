use rand::Rng;
use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use crate::connection_reliability_sender::ConnectionReliabilitySender;
use crate::connection_security::Security;
use crate::constants::{MAX_PAYLOAD_SIZE, RECEIVE_WINDOW_SIZE, TIME_WAIT_TIMEOUT};
use crate::cookie::ConnectionCookie;
use crate::packet::{Packet, PacketFlags, PrimaryHeader, SignatureHeader};
use crate::SecurityState;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum ConnectionState {
    Listen,
    CookieWait,
    CookieEchoed,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
    CloseWait,
    LastAck,
    Closed,
    Closing,
}

#[derive(Eq, PartialEq, Hash)]
pub enum PacketRetransmit {
    Init,
    CookieEcho,
    ArwndUpdate(u32),
    Data(u32),
}

pub struct Connection {
    addr: Arc<RwLock<SocketAddr>>,
    connection_id: u32,
    socket: UdpSocket,
    incoming: Mutex<VecDeque<Packet>>,

    connection_state: Arc<Mutex<ConnectionState>>,
    cookie: Option<ConnectionCookie>,
    current_send_sequence_number: u32,
    next_expected_sequence_number: u32,

    receive_channel: Sender<Vec<u8>>,
    client_data_receiver: Option<Receiver<Vec<u8>>>,

    reliable_sender: ConnectionReliabilitySender,

    pub security: Security,

    internal_buffer: usize,
    external_buffer: usize,
    channel_buffer: usize,

    is_client: bool,
    is_encrypted: bool,
}

impl Connection {
    pub fn new(
        addr: SocketAddr,
        socket: UdpSocket,
        connection_id: u32,
        is_client: bool,
        is_encrypted: bool,
        next_expected_sequence_number: u32,
    ) -> Connection {
        let mut rng = rand::thread_rng();
        let addr_container = Arc::new(RwLock::new(addr));

        let (receive_channel, client_data_receiver) = channel::<Vec<u8>>();

        Connection {
            reliable_sender: ConnectionReliabilitySender::new(
                addr_container.clone(),
                socket.try_clone().unwrap(),
            ),
            security: Security::new(is_encrypted),
            addr: addr_container,
            connection_id,
            socket,
            incoming: Mutex::new(VecDeque::new()),

            connection_state: Arc::new(Mutex::new(ConnectionState::Closed)),
            cookie: None,
            current_send_sequence_number: rng.gen(),
            next_expected_sequence_number,
            receive_channel,
            client_data_receiver: Some(client_data_receiver),

            internal_buffer: 0,
            external_buffer: 0,
            channel_buffer: 0,

            is_client,
            is_encrypted,
        }
    }

    pub fn get_receive_channel(&mut self) -> Receiver<Vec<u8>> {
        self.client_data_receiver.take().unwrap()
    }

    pub fn is_client(&self) -> bool {
        self.is_client
    }

    pub fn verify_cookie(&self, cookie: &ConnectionCookie) -> bool {
        if cookie.source_addr != self.get_addr()
            || cookie.connection_id != self.cookie.as_ref().unwrap().connection_id
            || cookie.hmac != self.cookie.as_ref().unwrap().hmac
        {
            return false;
        }

        true
    }

    pub fn receive_packet(&mut self, packet: Packet, src: SocketAddr) {
        if *self.addr.read().unwrap() != src {
            eprintln!("Destination has changed source");
            let mut addr = self.addr.write().unwrap();
            *addr = src;
        }

        self.reliable_sender.update_remote_arwnd(packet.get_arwnd());
        self.reliable_sender
            .update_local_arwnd(self.total_buffer_size());

        let packet_expected = self.check_a_after_b(
            packet.get_sequence_number(),
            self.next_expected_sequence_number,
        );

        // HANDLE INIT ACK packets
        if packet.is_ack() && packet.is_init() {
            self.next_expected_sequence_number =
                ((packet.get_sequence_number() as u64 + packet.payload_size() as u64) as u64
                    % 2u64.pow(32)) as u32;

            self.handle_init_ack(&packet);

            return;
        }

        // Handle COOKIE-ECHO packets
        // These packets should only have the cookie flag set
        // If we receive a cookie-echo, we need to verify it and respond with an ack
        if packet.is_cookie() && !packet.is_ack() {
            if packet.get_sequence_number() == self.next_expected_sequence_number {
                self.next_expected_sequence_number =
                    ((packet.get_sequence_number() as u64 + packet.payload_size() as u64) as u64
                        % 2u64.pow(32)) as u32;
            }

            self.handle_cookie_echo(packet);

            return;
        }

        // HANDLE COOKIE-ACK packets
        // These packets have both the cookie and ack flags set
        if packet.is_cookie() && packet.is_ack() {
            self.handle_cookie_ack(packet);

            return;
        }

        if packet.is_fin() {
            self.handle_fin(packet);

            return;
        }

        if packet.is_arwnd() && !packet.is_ack() {
            self.handle_arwnd_update(&packet);

            return;
        }

        // HANDLE DATA ACK packets
        if packet.is_ack() {
            self.handle_ack(&packet);
        }

        let connection_state = self.get_connection_state();

        // ignore packets when not in established phase
        if packet.payload_size() > 0
            || packet.is_sec()
                && connection_state != ConnectionState::CookieWait
                && connection_state != ConnectionState::CookieEchoed
        {
            let seq_num = packet.get_sequence_number();

            if packet_expected {
                self.insert_packet_incoming_queue(packet);
            }

            self.send_ack(seq_num);
        }

        if self.is_client()
            && self.security.state == SecurityState::Secured
            && self.security.key_expired()
        {
            eprintln!("[INFO] The key has expired. Exchanging a new one...");
            self.security.state = SecurityState::ChangeKeys;
            for mut packet in self.security.agree_on_algorithms_client() {
                packet.set_connection_id(self.get_connection_id());
                self.send_packet(packet);
            }
        }
    }

    pub fn insert_in_order(&mut self, packet: Packet) {
        let mut incoming = self.incoming.lock().unwrap();

        for (i, cur) in incoming.iter().enumerate() {
            // If we received a duplicate packet,
            // we should replace the old packet with the same sequence number with the new one
            if cur.get_sequence_number() == packet.get_sequence_number() {
                self.internal_buffer -= cur.payload_size();
                self.internal_buffer += packet.payload_size();

                incoming[i] = packet;
                return;
            }

            if !self.check_a_after_b(packet.get_sequence_number(), cur.get_sequence_number()) {
                self.internal_buffer += packet.payload_size();
                incoming.insert(i, packet);

                return;
            }
        }

        self.internal_buffer += packet.payload_size();
        incoming.push_back(packet);
    }

    fn check_a_after_b(&self, seq_num_a: u32, seq_num_b: u32) -> bool {
        if self.next_expected_sequence_number
            > ((RECEIVE_WINDOW_SIZE as usize * 10) * MAX_PAYLOAD_SIZE) as u32
        {
            let threshold = self.next_expected_sequence_number as usize
                - ((RECEIVE_WINDOW_SIZE as usize * 10) * MAX_PAYLOAD_SIZE);

            if (seq_num_a as usize) < threshold {
                return (seq_num_a as u64) + (u32::MAX as u64) >= seq_num_b as u64;
            }
        }

        seq_num_a >= seq_num_b
    }

    pub fn insert_packet_incoming_queue(&mut self, packet: Packet) {
        let mut packets_to_send: Vec<Packet> = Vec::new();

        // First insert the new packet in order in the incoming queue
        // This makes it trivial to simply return all packets
        self.insert_in_order(packet);

        {
            let mut incoming = self.incoming.lock().unwrap();

            while let Some(next_packet) = incoming.front() {
                if next_packet.get_sequence_number() != self.next_expected_sequence_number {
                    break;
                }

                let next_packet = incoming.pop_front().unwrap();

                self.next_expected_sequence_number = ((self.next_expected_sequence_number as u64
                    + next_packet.payload_size() as u64)
                    as u64
                    % 2u64.pow(32)) as u32;
                self.internal_buffer -= next_packet.payload_size();

                if next_packet.is_sec() {
                    packets_to_send.extend(Self::handle_sec_packet(
                        &mut self.security,
                        &next_packet,
                        self.is_client,
                        &mut self.is_encrypted,
                    ));

                    continue;
                }

                self.channel_buffer += next_packet.payload_size();

                let decrypted_payload = if self.is_encrypted {
                    match self.security.decrypt_bytes(
                        next_packet.get_payload(),
                        next_packet.get_signature().unwrap(),
                        self.is_client(),
                    ) {
                        Ok(payload) => payload,
                        Err(e) => panic!("{}", e),
                    }
                } else {
                    next_packet.get_payload()
                };

                self.receive_channel
                    .send(decrypted_payload)
                    .expect("Could not send incomming data to frontend");
            }
        }

        for mut packet in packets_to_send {
            packet.set_connection_id(self.get_connection_id());
            self.send_packet(packet);
        }
    }

    fn start_fin_timeout(&self) {
        let connection_state = self.connection_state.clone();

        thread::spawn(move || {
            thread::sleep(TIME_WAIT_TIMEOUT);
            *connection_state.lock().unwrap() = ConnectionState::Closed
        });
    }

    fn set_connection_state(&self, state: ConnectionState) {
        eprintln!("Going into state: {:?}", state);
        *self.connection_state.lock().unwrap() = state;

        if state == ConnectionState::TimeWait {
            self.start_fin_timeout();
        }
    }

    pub fn get_connection_state(&self) -> ConnectionState {
        *self.connection_state.lock().unwrap()
    }

    fn handle_sec_packet(
        security: &mut Security,
        packet: &Packet,
        is_client: bool,
        encrypted: &mut bool,
    ) -> Vec<Packet> {
        if packet.encryption_header.is_some() {
            // check if other user wants to disable encryption
            if packet.encryption_header.as_ref().unwrap().is_empty() {
                eprintln!("disable encryption!");
                security.set_encrypt(false);
                *encrypted = false;

                return if !is_client {
                    vec![Security::get_empty_encryption_packet()]
                } else {
                    Vec::new()
                };
            }

            if !security.got_entire_cert(packet.get_payload()) {
                eprintln!("Waiting for rest of the certificate...");
                return Vec::new();
            }

            if !(*encrypted) {
                eprintln!("disable encryption!");
                security.set_encrypt(false);
                *encrypted = false;
                return vec![Security::get_empty_encryption_packet()];
            }

            match security.check_certificate() {
                Ok(_) => {}
                Err(error) => {
                    eprintln!("{:?}", error); /* Go to CLOSED state */
                    return Vec::new();
                }
            }

            eprintln!("[INFO] The connection authenticity was checked successfully!");

            security.state = SecurityState::ExchangeKeys;
            if !is_client {
                return match security
                    .agree_on_algorithms_server(packet.encryption_header.as_ref().unwrap())
                {
                    Ok(packets) => packets,
                    Err((packets, error)) => {
                        eprintln!("{}", error);
                        /* Go to CLOSED state */
                        packets
                    }
                };
            } else {
                let header = packet.encryption_header.as_ref().unwrap();

                if header.supported_encryption_algorithms.is_empty()
                    || header.supported_signature_algorithms.is_empty()
                {
                    /* Go to CLOSED state */
                } else {
                    // we can take the first one since all algorithms parsed are supported by this protocol
                    security.set_algorithms(
                        header.supported_encryption_algorithms[0],
                        header.supported_signature_algorithms[0],
                    );

                    return vec![security.start_exchange_keys_client()];
                }
            }

            return Vec::new();
        }

        match security.state {
            SecurityState::ExchangeAlgorithms => {
                eprintln!("[WARNING] Packets without an EncryptionHeader are ignored in the ExchangeAlgorithms State!")
            }
            SecurityState::ExchangeKeys => {
                match packet.get_signature() {
                    None => panic!("The receive DH packet has no signature header!"),
                    Some(sig) => security.rsa_verify_signature(packet.get_payload(), sig),
                }

                if is_client {
                    security.end_exchange_keys_client(packet.get_payload());
                } else {
                    let packet = security.exchange_keys_server(packet.get_payload());
                    return vec![packet];
                }
            }
            SecurityState::Secured => {
                panic!("You should not be here!");
            }
            SecurityState::ChangeKeys => {
                panic!("You should not be here!");
            }
        }

        Vec::new()
    }

    pub fn handle_init_ack(&mut self, packet: &Packet) {
        // The only reason we should even be receiving an init ack is if we are a client.
        // The init ack contains the connection id we should use to communicate with the server.
        // Therefor we should set the connection id when we receive an init ack
        self.connection_id = packet.get_connection_id();

        self.handle_ack(packet);

        self.send_cookie_echo(packet.get_payload());
    }

    fn send_reset(&mut self) {
        eprintln!("Sending reset");

        // TODO: are there more things to clear?
        self.incoming.lock().unwrap().clear();
        self.reliable_sender =
            ConnectionReliabilitySender::new(self.addr.clone(), self.socket.try_clone().unwrap());

        let mut flags = PacketFlags::new(0);
        flags.reset = true;

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            vec![],
        );

        self.send_packet(packet);
    }

    pub fn handle_cookie_echo(&mut self, packet: Packet) {
        let cookie = ConnectionCookie::from_bytes(packet.get_payload());

        // handling expired cookie
        if self.cookie.as_ref().unwrap().has_expired() {
            self.send_reset();
        }

        let valid = self.verify_cookie(&cookie);

        if !valid {
            // just do nothing
            return;
        }

        self.send_cookie_ack();

        self.set_connection_state(ConnectionState::Established);
    }

    pub fn handle_cookie_ack(&mut self, packet: Packet) {
        self.set_connection_state(ConnectionState::Established);
        self.handle_ack(&packet);
    }

    pub fn handle_fin(&mut self, packet: Packet) {
        self.send_ack(packet.get_sequence_number());

        let connection_state = self.get_connection_state();

        // We don't want to close yet, but the other peer wants to close
        if connection_state == ConnectionState::Established {
            self.set_connection_state(ConnectionState::CloseWait);

            return;
        }

        // Simultaneous close
        if connection_state == ConnectionState::FinWait1 {
            self.set_connection_state(ConnectionState::Closing);

            return;
        }

        // We wanted to close, and now the server does too
        if connection_state == ConnectionState::FinWait2 {
            self.set_connection_state(ConnectionState::TimeWait);
        }
    }

    pub fn handle_ack(&mut self, packet: &Packet) {
        self.reliable_sender.handle_ack(packet);

        match self.get_connection_state() {
            ConnectionState::LastAck => self.set_connection_state(ConnectionState::Closed),
            ConnectionState::FinWait1 => {
                self.set_connection_state(ConnectionState::FinWait2);
            }
            ConnectionState::Closing => {
                self.set_connection_state(ConnectionState::TimeWait);
            }
            _ => {}
        }
    }

    pub fn handle_arwnd_update(&mut self, packet: &Packet) {
        // For an arwnd update packet, we only need to send an ack for the packet with the
        // arwnd flag set

        eprintln!("We recived arwnd update! Sending an arwnd update ack");

        let mut flags = PacketFlags::new(0);
        flags.ack = true;
        flags.arwnd_update = true;

        let packet = Packet::new(
            PrimaryHeader::new(
                self.connection_id,
                self.current_send_sequence_number,
                packet.get_sequence_number(),
                0,
                flags,
            ),
            None,
            None,
            vec![],
        );

        self.send_packet(packet);
    }

    pub fn send_packet(&mut self, mut packet: Packet) {
        // Set the sequence number for the packet
        packet.set_sequence_number(self.current_send_sequence_number);

        if !packet.is_sec() {
            let (enc_payload, signature) = self
                .security
                .encrypt_bytes(packet.get_payload(), self.is_client());

            // encrypt payload
            packet.set_payload(enc_payload);

            if !signature.is_empty() {
                packet.set_signature_header(SignatureHeader::new(signature));
            }
        }

        self.current_send_sequence_number = ((self.current_send_sequence_number as u64
            + packet.payload_size() as u64) as u64
            % 2u64.pow(32)) as u32;

        self.reliable_sender.send_packet(packet);

        // if the key expired we restart the security handshake
        if self.is_client()
            && self.security.state == SecurityState::Secured
            && self.security.key_expired()
        {
            eprintln!("[INFO] The key has expired. Exchanging a new one...");
            self.security.state = SecurityState::ChangeKeys;
            for mut packet in self.security.agree_on_algorithms_client() {
                packet.set_connection_id(self.get_connection_id());
                self.send_packet(packet);
            }
        }
    }

    fn send_ack(&mut self, seq_num: u32) {
        let mut flags = PacketFlags::new(0);
        flags.ack = true;

        let packet = Packet::new(
            PrimaryHeader::new(
                self.connection_id,
                self.current_send_sequence_number,
                seq_num,
                0,
                flags,
            ),
            None,
            None,
            vec![],
        );

        self.send_packet(packet);
    }

    pub fn send_data(&mut self, payload: Vec<u8>) {
        self.append_to_send_queue(payload);
    }

    fn append_to_send_queue(&mut self, payload: Vec<u8>) {
        let chunks: Vec<&[u8]> = payload.chunks(MAX_PAYLOAD_SIZE).collect();

        for chunk in chunks {
            self.send_packet(self.create_packet_for_data(Vec::from(chunk)));
        }
    }

    fn create_packet_for_data(&self, payload: Vec<u8>) -> Packet {
        let flags = PacketFlags::new(0);

        Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            payload,
        )
    }

    pub fn send_init(&mut self) {
        let mut flags = PacketFlags::new(0);
        flags.init = true;

        let packet = Packet::new(PrimaryHeader::new(0, 0, 0, 0, flags), None, None, vec![]);
        self.send_packet(packet);
    }

    pub fn send_init_ack(&mut self) {
        self.set_connection_state(ConnectionState::Listen);

        let mut flags = PacketFlags::new(0);
        flags.init = true;
        flags.ack = true;

        // sign cookie and save MAC
        self.cookie = Some(ConnectionCookie::new(self.get_addr(), self.connection_id));

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            self.cookie.as_ref().unwrap().to_bytes(true),
        );

        self.send_packet(packet);
    }

    pub fn send_cookie_echo(&mut self, cookie: Vec<u8>) {
        let mut flags = PacketFlags::new(0);
        flags.cookie = true;

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            cookie,
        );

        self.set_connection_state(ConnectionState::CookieEchoed);

        self.send_packet(packet);
    }

    pub fn send_cookie_ack(&mut self) {
        let mut flags = PacketFlags::new(0);
        flags.cookie = true;
        flags.ack = true;

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            vec![],
        );

        self.send_packet(packet);
    }

    pub fn send_arwnd_update(&mut self) {
        let mut flags = PacketFlags::new(0);
        flags.arwnd_update = true;

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            vec![],
        );

        self.send_packet(packet);
    }

    pub fn send_fin(&mut self) {
        let mut flags = PacketFlags::new(0);
        flags.fin = true;

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            vec![],
        );

        self.wait_for_last_ack();

        self.send_packet(packet);

        if self.get_connection_state() == ConnectionState::CloseWait {
            self.set_connection_state(ConnectionState::LastAck)
        }

        if self.get_connection_state() == ConnectionState::Established {
            self.set_connection_state(ConnectionState::FinWait1)
        }
    }

    fn total_buffer_size(&self) -> usize {
        self.external_buffer + self.channel_buffer + self.internal_buffer
    }

    pub fn update_external_buffer_size(&mut self, buffer_size: usize) {
        let max_buffer_size = RECEIVE_WINDOW_SIZE as usize * MAX_PAYLOAD_SIZE;

        let mut old_arwnd = 0;

        if self.total_buffer_size() < max_buffer_size {
            old_arwnd = max_buffer_size - self.total_buffer_size();
        }

        self.external_buffer = buffer_size;

        self.reliable_sender
            .update_local_arwnd(self.total_buffer_size());

        let mut new_arwnd = 0;

        if self.total_buffer_size() < max_buffer_size {
            new_arwnd = max_buffer_size - self.total_buffer_size();
        }

        // If the total buffer size has changed by 5%,
        // we are supposed to send an arwnd update.
        // This is done to prevent a deadlock.
        if (new_arwnd as f64 - old_arwnd as f64) / old_arwnd as f64 > 0.05
            && self.get_connection_state() == ConnectionState::Established
        {
            self.send_arwnd_update();
        }
    }

    pub fn reset_channel_buffer_size(&mut self) {
        self.channel_buffer = 0;
    }

    pub fn can_send(&self) -> bool {
        self.reliable_sender.can_send()
    }

    pub fn get_addr(&self) -> SocketAddr {
        *self.addr.read().unwrap()
    }

    pub fn get_connection_id(&self) -> u32 {
        self.connection_id
    }

    pub fn set_connection_id(&mut self, connection_id: u32) {
        self.connection_id = connection_id;
    }

    pub fn connection_can_close(&self) -> bool {
        self.reliable_sender.get_in_flight() == 0
    }

    pub fn wait_for_last_ack(&self) {
        while !self.connection_can_close() {}
    }

    pub fn close(&mut self) {
        self.send_fin();
    }

    pub fn is_connection_closed(&self) -> bool {
        self.get_connection_state() == ConnectionState::Closed
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        eprintln!("connection dropped");
    }
}

#[cfg(test)]
mod packet {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

    use crate::connection::Connection;
    use crate::packet::{Packet, PacketFlags, PrimaryHeader};

    //#[test]
    pub fn append_to_send_queue() {
        let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 1200);
        let mut con = Connection::new(addr, UdpSocket::bind(addr).unwrap(), 0, true, false, 0);

        let rx = con.get_receive_channel();

        for i in [0, 3, 2, 1, 6, 4, 5, 9, 8, 7] {
            con.insert_packet_incoming_queue(Packet::new(
                PrimaryHeader::new(0, i, 0, 0, PacketFlags::new(0)),
                None,
                None,
                vec![i as u8],
            ));
        }

        for (i, _cur) in con.incoming.lock().unwrap().iter().enumerate() {
            assert_eq!(i as u8, rx.recv().unwrap()[0]);
        }
    }

    #[test]
    pub fn test_to_bytes() {}
}
