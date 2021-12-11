use crate::constants::{MAX_PAYLOAD_SIZE, RETRANSMISSION_TIMEOUT, TIME_WAIT_TIMEOUT};
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
    sending_queue_tx: Option<Sender<Packet>>,
    in_transit_queue_tx: Option<Sender<TimeoutPacket>>,

    in_transit: Arc<Mutex<HashMap<PacketRetransmit, bool>>>,
    connection_state: Arc<Mutex<ConnectionState>>,
    cookie: Option<ConnectionCookie>,
    current_send_sequence_number: u32,
    next_expected_sequence_number: u32,

    pub packet_counter: u32,
    receive_channel: Option<Sender<Vec<u8>>>,
}

struct TimeoutPacket {
    send_time: SystemTime,
    packet: Packet,
}

impl TimeoutPacket {
    pub fn timed_out(&self) -> bool {
        SystemTime::now().duration_since(self.send_time).unwrap() > RETRANSMISSION_TIMEOUT
    }
}

impl Connection {
    pub fn new(
        addr: SocketAddr,
        socket: UdpSocket,
        connection_id: Option<u32>,
        cookie: Option<ConnectionCookie>,
    ) -> Connection {
        let connection_id = match connection_id {
            None => rand::random(),
            Some(connection_id) => connection_id,
        };

        Connection {
            addr,
            connection_id,
            socket,
            incoming: Mutex::new(VecDeque::new()),

            sending_queue_tx: None,
            in_transit_queue_tx: None,
            in_transit: Arc::new(Mutex::new(HashMap::new())),

            connection_state: Arc::new(Mutex::new(ConnectionState::Closed)),
            cookie: None,
            current_send_sequence_number: 0,
            next_expected_sequence_number: 0,
            packet_counter: 0,
            receive_channel: None,
        }
    }

    pub fn register_receive_channel(&mut self) -> Receiver<Vec<u8>> {
        let (send, receive_channel) = channel::<Vec<u8>>();
        self.receive_channel = Some(send);
        return receive_channel;
    }

    pub fn start_threads(&mut self) {
        let (sending_queue_tx, sending_queue_rx) = channel::<Packet>();
        let (transit_queue_tx, transit_queue_rx) = channel::<TimeoutPacket>();

        self.sending_queue_tx = Some(sending_queue_tx);
        self.in_transit_queue_tx = Some(transit_queue_tx);

        self.start_send_thread(sending_queue_rx);
        self.start_timeout_monitor_thread(transit_queue_rx);
    }

    pub fn start_send_thread(&mut self, sending_queue_rx: Receiver<Packet>) {
        let in_transit = self.in_transit.clone();
        let in_transit_queue = self.in_transit_queue_tx.as_ref().unwrap().clone();

        let addr = self.addr.clone();
        let socket = self.socket.try_clone().unwrap();

        thread::spawn(move || {
            loop {
                let packet = sending_queue_rx.recv().unwrap();

                match socket.send_to(&*packet.to_bytes(), addr) {
                    Ok(_) => {
                        println!("Actually sending: {:?}", packet)
                    }
                    Err(_) => {
                        println!("We failed to send a packet!?")
                    }
                };

                // Don't bother checking if an ACK packet is still in transit
                // This should handle cookie ACKs aswell since they dont have a payload and have
                // the ack flag set. Why?
                if packet.is_ack() && packet.payload_size() == 0 {
                    continue;
                }

                //We don't care if the cookie ack arrives
                if packet.is_cookie() && packet.is_ack() {
                    continue;
                }

                if packet.is_ack() && packet.is_init() {
                    continue;
                }

                // We need to keep track of which packets are currently in transit
                // so we can accept acknowledgements for them later
                let mut packet_classification =
                    PacketRetransmit::Data(packet.get_sequence_number());

                if packet.is_init() {
                    packet_classification = PacketRetransmit::Init;
                } else if packet.is_cookie() {
                    packet_classification = PacketRetransmit::CookieEcho;
                }

                in_transit
                    .lock()
                    .unwrap()
                    .insert(packet_classification, false);

                in_transit_queue.send(TimeoutPacket {
                    send_time: SystemTime::now(),
                    packet,
                });
            }
        });
    }

    fn start_timeout_monitor_thread(&self, transit_queue_rx: Receiver<TimeoutPacket>) {
        let sending_queue_tx = self.sending_queue_tx.as_ref().unwrap().clone();
        let in_transit = self.in_transit.clone();

        thread::spawn(move || loop {
            let current_timeout_packet = transit_queue_rx.recv().unwrap();

            if !current_timeout_packet.timed_out() {
                let deadline = current_timeout_packet.send_time + RETRANSMISSION_TIMEOUT;
                let time_to_wait = deadline.duration_since(SystemTime::now()).unwrap();

                thread::sleep(time_to_wait)
            }

            let mut packet_classification =
                PacketRetransmit::Data(current_timeout_packet.packet.get_sequence_number());

            if current_timeout_packet.packet.is_init() {
                packet_classification = PacketRetransmit::Init;
            }

            if current_timeout_packet.packet.is_cookie() {
                packet_classification = PacketRetransmit::CookieEcho;
            }

            let ack_received = in_transit
                .lock()
                .unwrap()
                .remove(&packet_classification)
                .unwrap();

            if !ack_received {
                println!("Packet timed out: {:?}", current_timeout_packet.packet);
                sending_queue_tx.send(current_timeout_packet.packet);
            }
        });
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
        let mut packet_expected = true;

        println!(
            "Recevied packet: {}. Expected: {}",
            packet.get_sequence_number(),
            self.next_expected_sequence_number
        );

        if packet.get_sequence_number() < self.next_expected_sequence_number {
            packet_expected = false;
        }

        // HANDLE INIT ACK packets
        if packet.is_ack() && packet.is_init() {
            if packet.get_sequence_number() == self.next_expected_sequence_number {
                self.next_expected_sequence_number =
                    packet.get_sequence_number() + packet.payload_size();
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
                    packet.get_sequence_number() + packet.payload_size();
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
                    packet.get_sequence_number() + packet.payload_size();
            }

            println!("Sending ack for {}", packet.get_sequence_number());
            self.send_ack(packet.get_sequence_number());

            if packet_expected {
                println!("Packet was expected. Writing it into buffer");
                self.insert_packet_incoming_queue(packet, packet_expected);
            }
        }
    }

    pub fn insert_packet_incoming_queue(&mut self, packet: Packet, packet_expected: bool) {
        let mut incoming = self.incoming.lock().unwrap();

        if packet_expected {
            // send to packet to receive channel
            self.receive_channel
                .as_ref()
                .unwrap()
                .send(packet.get_payload());

            let mut last_index = 0;
            let mut next_expected_sequence_number =
                packet.get_sequence_number() + packet.payload_size();

            for (index, current_packet) in incoming.iter().enumerate() {
                // find following packet
                if current_packet.get_sequence_number() == next_expected_sequence_number {
                    last_index = index;
                    next_expected_sequence_number += current_packet.payload_size();
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
        println!("Starting timeout");

        let connection_state = self.connection_state.clone();

        thread::spawn(move || {
            thread::sleep(TIME_WAIT_TIMEOUT);
            *connection_state.lock().unwrap() = ConnectionState::Closed
        });
    }

    fn set_connection_state(&self, state: ConnectionState) {
        println!("Setting connection to: {:?}", state);

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
        println!("Received cookie echo");
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
        println!("Handling cookie ack");
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

        println!(
            "received fin while in invalid state. Our ack probably never arrived {:?}",
            self.connection_state
        );
    }

    pub fn handle_ack(&mut self, packet: &Packet) {
        println!("received an ack for {}", packet.get_ack_number());

        let mut packet_classification = PacketRetransmit::Data(packet.get_ack_number());

        if packet.is_init() {
            packet_classification = PacketRetransmit::Init;
        }

        if packet.is_cookie() {
            packet_classification = PacketRetransmit::CookieEcho;
        }

        let duplicate = {
            let mut in_transit_lock = self.in_transit.lock().unwrap();

            match in_transit_lock.insert(packet_classification, true) {
                None => true,
                Some(duplicate) => duplicate,
            }
        };

        if !duplicate {
            self.decrement_packet_counter();
        }

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

    fn increment_packet_counter(&mut self) {
        println!(
            "Going to increment the packet counter! {} {:p} {:p}",
            self.packet_counter, &self.packet_counter, self
        );
        self.packet_counter += 1;
        println!(
            "We incremented the packet counter! {} {:p} {:p}",
            self.packet_counter, &self.packet_counter, self
        )
    }

    fn decrement_packet_counter(&mut self) {
        println!(
            "Going to decrement packet counter! {} {:p} {:p}",
            self.packet_counter, &self.packet_counter, self
        );
        self.packet_counter -= 1;
        println!(
            "We decremented the packet counter! {} {:p} {:p}",
            self.packet_counter, &self.packet_counter, self
        )
    }

    fn send_packet(&mut self, mut packet: Packet) {
        if packet.is_ack() && packet.is_init() {
            //self.packet_counter += 1;
        }

        // Set the sequence number for the packet
        packet.set_sequence_number(self.current_send_sequence_number);

        self.current_send_sequence_number += packet.payload_size();

        println!(
            "Queueing packet {}. {:?}",
            packet.get_sequence_number(),
            packet
        );

        if !packet.is_ack() {
            self.increment_packet_counter();
        }

        self.sending_queue_tx.as_ref().unwrap().send(packet);
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

    pub fn create_packet_for_data(&self, payload: Vec<u8>) -> Packet {
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
        println!("Sending cookie echo");
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

    pub fn get_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn get_connection_id(&self) -> u32 {
        self.connection_id
    }

    pub fn set_conncetion_id(&mut self, connection_id: u32) {
        self.connection_id = connection_id;
    }

    pub fn connection_can_close(&self) -> bool {
        self.packet_counter == 0
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
        println!("connection dropped");
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
        let mut con = Connection::new(addr, UdpSocket::bind(addr).unwrap(), None, None);

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
