use crate::constants::{MAX_PAYLOAD_SIZE, RETRANSMISSION_TIMEOUT};
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

pub struct Connection {
    addr: SocketAddr,
    connection_id: u32,
    socket: UdpSocket,
    incoming: Mutex<VecDeque<Packet>>,
    sending_queue_tx: Option<Sender<Packet>>,
    in_transit_queue_tx: Option<Sender<TimeoutPacket>>,

    in_transit: Arc<Mutex<HashMap<u32, bool>>>,
    connection_state: Mutex<ConnectionState>,
    cookie: Option<ConnectionCookie>,
    current_send_sequence_number: Arc<Mutex<u32>>,
    next_expected_sequence_number: Arc<Mutex<u32>>,
    proccessing_retransmit: Arc<Mutex<bool>>,
    processing_sending: Arc<Mutex<bool>>,
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

        // The starting state should be cookie wait if we are a client
        let mut current_state = ConnectionState::CookieWait;
        let mut starting_sequence_number: u32 = 0;

        if cookie.is_none() {
            current_state = ConnectionState::Listen;
        }

        if cookie.is_some() {
            starting_sequence_number = cookie.as_ref().unwrap().get_size() as u32;
        }

        Connection {
            addr,
            connection_id,
            socket,
            incoming: Mutex::new(VecDeque::new()),

            sending_queue_tx: None,
            in_transit_queue_tx: None,
            in_transit: Arc::new(Mutex::new(HashMap::new())),

            connection_state: Mutex::new(current_state),
            cookie,
            current_send_sequence_number: Arc::new(Mutex::new(0)),
            next_expected_sequence_number: Arc::new(Mutex::new(starting_sequence_number)),
            proccessing_retransmit: Arc::new(Mutex::new(false)),
            processing_sending: Arc::new(Mutex::new(false)),
        }
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
        let processing_sending = self.processing_sending.clone();

        thread::spawn(move || {
            loop {
                let packet = sending_queue_rx.recv().unwrap();

                {
                    *processing_sending.lock().unwrap() = true;
                }

                match socket.send_to(&*packet.to_bytes(), addr) {
                    Ok(_) => {}
                    Err(_) => {
                        println!("We failed to send a packet!?")
                    }
                };

                // Don't bother checking if an ACK packet is still in transit
                if packet.is_ack() && packet.payload_size() == 0 {
                    continue;
                }

                // We don't care if the cookie ack arrives
                if packet.is_cookie() && packet.is_ack() {
                    continue;
                }

                // We need to keep track of which packets are currently in transit
                // so we can accept acknowledgements for them later
                in_transit
                    .lock()
                    .unwrap()
                    .insert(packet.get_sequence_number(), false);

                in_transit_queue.send(TimeoutPacket {
                    send_time: SystemTime::now(),
                    packet,
                });

                {
                    *processing_sending.lock().unwrap() = false;
                }
            }
        });
    }

    fn start_timeout_monitor_thread(&self, transit_queue_rx: Receiver<TimeoutPacket>) {
        let sending_queue_tx = self.sending_queue_tx.as_ref().unwrap().clone();
        let in_transit = self.in_transit.clone();
        let proccessing_retransmit = self.proccessing_retransmit.clone();

        thread::spawn(move || loop {
            {
                let current_timeout_packet = transit_queue_rx.recv().unwrap();

                if !current_timeout_packet.timed_out() {
                    thread::sleep(
                        SystemTime::now()
                            .duration_since(
                                current_timeout_packet.send_time + RETRANSMISSION_TIMEOUT,
                            )
                            .unwrap(),
                    )
                }

                {
                    *proccessing_retransmit.lock().unwrap() = true;
                }

                let ack_received = in_transit
                    .lock()
                    .unwrap()
                    .remove(&current_timeout_packet.packet.get_sequence_number())
                    .unwrap();

                if !ack_received {
                    sending_queue_tx.send(current_timeout_packet.packet);
                }

                {
                    *proccessing_retransmit.lock().unwrap() = false;
                }
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
        let expected_sequence_number = { *self.next_expected_sequence_number.lock().unwrap() };
        let mut packet_expected = true;

        println!(
            "Received packet {}. Expected {}, {:?}",
            packet.get_sequence_number(),
            expected_sequence_number,
            packet
        );

        if (packet.get_sequence_number() < expected_sequence_number) {
            packet_expected = false;
        }

        if packet.get_sequence_number() == expected_sequence_number {
            *self.next_expected_sequence_number.lock().unwrap() =
                packet.get_sequence_number() + packet.payload_size();
        }

        // Handle COOKIE-ECHO packets
        // These packets should only have the cookie flag set
        // If we receive a cookie-echo, we need to verify it and respond with an ack
        if packet.is_cookie() && !packet.is_ack() {
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

        if packet.payload_size() > 0 {
            println!("Sending ack for {}", packet.get_sequence_number());
            self.send_ack(packet.get_sequence_number());

            if packet_expected {
                self.insert_packet_incoming_queue(packet);
            }
        } else {
            println!(
                "Payload size of {} is 0. Not sending ack",
                packet.get_sequence_number()
            );
        }
    }

    pub fn insert_packet_incoming_queue(&self, packet: Packet) {
        let mut incoming = self.incoming.lock().unwrap();

        for (i, cur) in incoming.iter().enumerate() {
            if cur.get_sequence_number() > packet.get_sequence_number() {
                incoming.insert(i, packet);

                return;
            }
        }

        incoming.push_back(packet);
    }

    fn set_connection_state(&self, state: ConnectionState) {
        *self.connection_state.lock().unwrap() = state;
    }

    pub fn get_connection_state(&self) -> ConnectionState {
        *self.connection_state.lock().unwrap()
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

        // Remove the init-ack from the in-transit queue.
        // If we are handling a cookie-echo, it means it has arrived
        self.in_transit.lock().unwrap().remove(&(0 as u32));

        self.set_connection_state(ConnectionState::Established);

        self.send_cookie_ack();
    }

    pub fn handle_cookie_ack(&mut self, packet: Packet) {
        println!("Handling cookie ack");
        self.handle_ack(&packet);
        println!("Setting connection state to established");
        self.set_connection_state(ConnectionState::Established);
    }

    pub fn handle_fin(&mut self, packet: Packet) {
        self.send_ack(packet.get_sequence_number());

        let connection_state = self.connection_state.lock().unwrap();

        // We don't want to close yet, but the other peer wants to close
        if *connection_state == ConnectionState::Established {
            self.set_connection_state(ConnectionState::CloseWait);

            return;
        }

        // Simultaneous close
        if *connection_state == ConnectionState::FinWait1 {
            self.set_connection_state(ConnectionState::Closing);

            return;
        }

        // We wanted to close, and now the server does too
        if *connection_state == ConnectionState::FinWait2 {
            self.set_connection_state(ConnectionState::TimeWait);

            return;
        }

        panic!("Invalid state when received fin {:?}", connection_state);
    }

    pub fn handle_ack(&mut self, packet: &Packet) {
        println!("Set packet {} as received", &packet.get_ack_number());

        self.in_transit
            .lock()
            .unwrap()
            .insert(packet.get_ack_number(), true);
    }

    pub fn can_recv(&self) -> bool {
        let incoming = self.incoming.lock().unwrap();

        //println!("{}, {}", incoming.len(), incoming.is_empty());

        return !incoming.is_empty();
    }

    pub fn recv(&mut self) -> Vec<u8> {
        let mut incoming = self.incoming.lock().unwrap();
        let mut output: Vec<u8> = Vec::new();

        for packet in incoming.iter() {
            output.append(&mut packet.get_payload());
        }

        incoming.clear();

        return output;
    }

    fn send_packet(&self, mut packet: Packet) {
        let mut seq_num = self.current_send_sequence_number.lock().unwrap();
        // Set the sequence number for the packet
        packet.set_sequence_number(*seq_num);

        println!("Sending packet {}: {:?}", *seq_num, packet);

        *seq_num += packet.payload_size();

        self.sending_queue_tx.as_ref().unwrap().send(packet);
    }

    fn send_ack(&self, seq_num: u32) {
        let mut flags = PacketFlags::new(0);
        flags.ack = true;

        let packet = Packet::new(
            PrimaryHeader::new(
                self.connection_id,
                *self.current_send_sequence_number.lock().unwrap(),
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

    pub fn send_data(&self, payload: Vec<u8>) {
        self.append_to_send_queue(payload);
    }

    fn append_to_send_queue(&self, payload: Vec<u8>) {
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

    pub fn send_init_ack(&mut self) {
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

    pub fn send_cookie_ack(&self) {
        let cookie = self.cookie.as_ref().unwrap();

        let mut flags = PacketFlags::new(0);
        flags.cookie = true;
        flags.ack = true;

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            cookie.to_bytes(),
        );

        self.send_packet(packet);
    }

    pub fn send_fin(&self) {
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

    pub fn connection_can_close(&self) -> bool {
        println!("Checking in transit count");
        let in_transit_count = self.in_transit.lock().unwrap().len();

        in_transit_count == 0
    }

    pub fn wait_for_last_ack(&self) {
        while !self.connection_can_close() {}
    }

    fn close_connection(&self) {
        self.set_connection_state(ConnectionState::Closed)
    }

    pub fn close(&self) {
        self.send_fin();
    }

    pub fn is_connection_closed(&self) -> bool {
        self.get_connection_state() == ConnectionState::Closed
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
        let con = Connection::new(addr, UdpSocket::bind(addr).unwrap(), None, None);

        for i in [0, 3, 2, 1, 6, 4, 5, 9, 8, 7] {
            con.insert_packet_incoming_queue(Packet::new(
                PrimaryHeader::new(0, i, 0, 0, PacketFlags::new(0)),
                None,
                None,
                vec![],
            ));
        }

        for (i, cur) in con.incoming.lock().unwrap().iter().enumerate() {
            assert_eq!(i as u32, cur.get_sequence_number());
        }
    }

    #[test]
    pub fn test_to_bytes() {}
}
