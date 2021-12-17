use crate::connection_reliability_sender::ConnectionReliabilitySender;
use crate::constants::{MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE, TIME_WAIT_TIMEOUT};
use crate::cookie::ConnectionCookie;
use crate::packet::{Packet, PacketFlags, PrimaryHeader};
use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

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
    Data(u32),
}

pub struct Connection {
    addr: SocketAddr,
    connection_id: u32,
    socket: UdpSocket,
    incoming: Mutex<VecDeque<Packet>>,

    connection_state: Arc<Mutex<ConnectionState>>,
    cookie: Option<ConnectionCookie>,
    current_send_sequence_number: u32,
    next_expected_sequence_number: u32,

    receive_channel: Option<Sender<Vec<u8>>>,

    reliable_sender: ConnectionReliabilitySender,

    internal_buffer: usize,
    external_buffer: usize,
    channel_buffer: usize,
}

impl Connection {
    pub fn new(
        addr: SocketAddr,
        socket: UdpSocket,
        connection_id: u32,
        cookie: Option<ConnectionCookie>,
    ) -> Connection {
        Connection {
            reliable_sender: ConnectionReliabilitySender::new(
                addr.clone(),
                socket.try_clone().unwrap(),
            ),
            addr,
            connection_id,
            socket,
            incoming: Mutex::new(VecDeque::new()),

            connection_state: Arc::new(Mutex::new(ConnectionState::Closed)),
            cookie: None,
            current_send_sequence_number: 0,
            next_expected_sequence_number: 0,
            receive_channel: None,

            internal_buffer: 0,
            external_buffer: 0,
            channel_buffer: 0,
        }
    }

    pub fn register_receive_channel(&mut self) -> Receiver<Vec<u8>> {
        let (send, receive_channel) = channel::<Vec<u8>>();
        self.receive_channel = Some(send);
        return receive_channel;
    }

    pub fn start_receive_thread(&self) {}

    pub fn verify_cookie(&self, cookie: &ConnectionCookie) -> bool {
        // TODO: Calculate MAC (Cookie Signature)
        if cookie.source_addr != self.addr {
            return false;
        }

        true
    }

    pub fn receive_packet(&mut self, packet: Packet) {
        eprintln!("New arwnd: {}", packet.get_arwnd());
        self.reliable_sender.update_remote_arwnd(packet.get_arwnd());
        self.reliable_sender
            .update_local_arwnd(self.total_buffer_size());

        let mut packet_expected =
            packet.get_sequence_number() >= self.next_expected_sequence_number;

        // HANDLE INIT ACK packets
        if packet.is_ack() && packet.is_init() {
            if packet.get_sequence_number() == self.next_expected_sequence_number {
                self.next_expected_sequence_number =
                    packet.get_sequence_number() + packet.payload_size() as u32;
            }

            self.handle_init_ack(&packet);

            return;
        }

        // Handle COOKIE-ECHO packets
        // These packets should only have the cookie flag set
        // If we receive a cookie-echo, we need to verify it and respond with an ack
        if packet.is_cookie() && !packet.is_ack() {
            if packet.get_sequence_number() == self.next_expected_sequence_number {
                self.next_expected_sequence_number =
                    packet.get_sequence_number() + packet.payload_size() as u32;
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

        // HANDLE DATA ACK packets
        if packet.is_ack() {
            self.handle_ack(&packet);
        }

        let connection_state = self.get_connection_state();

        // ignore packets when not in established phase
        if packet.payload_size() > 0
            && connection_state != ConnectionState::CookieWait
            && connection_state != ConnectionState::CookieEchoed
        {
            if packet.get_sequence_number() == self.next_expected_sequence_number {
                self.next_expected_sequence_number =
                    packet.get_sequence_number() + packet.payload_size() as u32;
            }

            let seq_num = packet.get_sequence_number();

            if packet_expected {
                self.internal_buffer += packet.payload_size();
            }

            if packet_expected {
                self.insert_packet_incoming_queue(packet, packet_expected);
            }

            self.send_ack(seq_num);
        }
        eprintln!("packet handler finished");
    }

    pub fn insert_packet_incoming_queue(&mut self, packet: Packet, packet_expected: bool) {
        let mut incoming = self.incoming.lock().unwrap();

        if packet.get_sequence_number() < self.next_expected_sequence_number {
            // send to packet to receive channel
            self.channel_buffer += packet.payload_size();
            self.internal_buffer -= packet.payload_size();
            self.receive_channel
                .as_ref()
                .unwrap()
                .send(packet.get_payload());

            let mut last_index = 0;
            let mut next_expected_sequence_number =
                packet.get_sequence_number() + packet.payload_size() as u32;

            for (index, current_packet) in incoming.iter().enumerate() {
                // find following packet
                if current_packet.get_sequence_number() == next_expected_sequence_number {
                    last_index = index;
                    next_expected_sequence_number += current_packet.payload_size() as u32;

                    if self.internal_buffer > current_packet.payload_size() {
                        self.internal_buffer -= current_packet.payload_size();
                    } else {
                        eprintln!(
                            "A payload counting bug has occurred. Continuing because not critical"
                        );
                        //self.internal_buffer = 0;
                    }
                    self.channel_buffer += current_packet.payload_size();

                    self.receive_channel
                        .as_ref()
                        .unwrap()
                        .send(current_packet.get_payload());
                }
            }

            self.next_expected_sequence_number = next_expected_sequence_number;

            // remove all packets that were delivered to the application
            incoming.drain(std::ops::Range {
                start: 0,
                end: last_index,
            });

            return;
        }
        for (i, cur) in incoming.iter().enumerate() {
            if cur.get_sequence_number() > packet.get_sequence_number() {
                incoming.insert(i, packet);

                return;
            }
        }

        incoming.push_back(packet);
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

    pub fn handle_init_ack(&mut self, packet: &Packet) {
        // The only reason we should even be receiving an init ack is if we are a client.
        // The init ack contains the connection id we should use to communicate with the server.
        // Therefor we should set the connection id when we receive an init ack
        self.connection_id = packet.get_connection_id();

        // The init ack also contains the cookie
        self.cookie = Some(ConnectionCookie::from_bytes(packet.get_payload()));

        self.handle_ack(packet);

        self.send_cookie_echo();
    }

    pub fn handle_cookie_echo(&mut self, packet: Packet) {
        let cookie = ConnectionCookie::from_bytes(packet.get_payload());

        // TODO: Handle expired cookie
        //       This is *very* unlikely to happen

        let valid = self.verify_cookie(&cookie);

        if !valid {
            // TODO: Handle invalid cookie
            //       Close the connection maybe?
            //       Send a reset?
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

            return;
        }
    }

    pub fn handle_ack(&mut self, packet: &Packet) {
        eprintln!("Passing to reliable sender");
        self.reliable_sender.handle_ack(packet);
        eprintln!("reliable sender finished");

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

    fn send_packet(&mut self, mut packet: Packet) {
        // Set the sequence number for the packet
        packet.set_sequence_number(self.current_send_sequence_number);

        self.current_send_sequence_number += packet.payload_size() as u32;

        self.reliable_sender.send_packet(packet);
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
        eprintln!("Creating packet");
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

        // TODO: sign cookie and save MAC
        self.cookie = Some(ConnectionCookie::new(self.addr, self.connection_id));

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            self.cookie.as_ref().unwrap().to_bytes(),
        );

        self.send_packet(packet);
    }

    pub fn send_cookie_echo(&mut self) {
        let cookie = self.cookie.as_ref().unwrap();

        let mut flags = PacketFlags::new(0);
        flags.cookie = true;

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            cookie.to_bytes(),
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
        self.external_buffer = buffer_size;

        self.reliable_sender
            .update_local_arwnd(self.total_buffer_size());

        eprintln!(
            "local buffer has changed: {}. Next expected seq: {}",
            self.total_buffer_size(),
            self.next_expected_sequence_number
        );
    }

    pub fn reset_channel_buffer_size(&mut self) {
        self.channel_buffer = 0;
    }

    pub fn get_in_flight(&self) -> u32 {
        return self.reliable_sender.get_in_flight();
    }

    pub fn can_send(&self) -> bool {
        self.reliable_sender.can_send()
    }

    pub fn get_addr(&self) -> SocketAddr {
        self.addr
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
    use crate::connection::Connection;
    use crate::packet::{Packet, PacketFlags, PrimaryHeader};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

    #[test]
    pub fn append_to_send_queue() {
        let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 1200);
        let mut con = Connection::new(addr, UdpSocket::bind(addr).unwrap(), 0, None);

        for i in [0, 3, 2, 1, 6, 4, 5, 9, 8, 7] {
            con.insert_packet_incoming_queue(
                Packet::new(
                    PrimaryHeader::new(0, i, 0, 0, PacketFlags::new(0)),
                    None,
                    None,
                    vec![],
                ),
                false,
            );
        }

        for (i, cur) in con.incoming.lock().unwrap().iter().enumerate() {
            assert_eq!(i as u32, cur.get_sequence_number());
        }
    }

    #[test]
    pub fn test_to_bytes() {}
}
