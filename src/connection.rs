use crate::constants::{MAX_PAYLOAD_SIZE, RETRANSMISSION_TIMEOUT};
use crate::cookie::ConnectionCookie;
use crate::packet::{Packet, PacketFlags, PrimaryHeader};
use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

#[derive(Eq, PartialEq, Copy, Clone)]
pub enum ConnectionState {
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
    sending_queue: Arc<Mutex<VecDeque<Packet>>>,
    in_transit: Arc<Mutex<HashMap<u32, TimeoutPacket>>>,
    connection_state: Mutex<ConnectionState>,
    cookie: Option<ConnectionCookie>,
    current_send_sequence_number: Arc<Mutex<u32>>,
}

struct TimeoutPacket {
    send_time: SystemTime,
    packet: Packet,
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
            sending_queue: Arc::new(Mutex::new(VecDeque::new())),
            in_transit: Arc::new(Mutex::new(HashMap::new())),
            connection_state: Mutex::new(ConnectionState::CookieWait),
            cookie,
            current_send_sequence_number: Arc::new(Mutex::new(0)),
        }
    }

    pub fn start_threads(&self) {
        self.start_connection_thread();
        self.start_timeout_monitor_thread();
    }

    pub fn start_connection_thread(&self) {
        let sending_queue = self.sending_queue.clone();
        let in_transit = self.in_transit.clone();
        let addr = self.addr.clone();
        let socket = self.socket.try_clone().unwrap();

        thread::spawn(move || {
            loop {
                let first_packet = { sending_queue.lock().unwrap().pop_front() };

                if let Some(packet) = first_packet {
                    match socket.send_to(&*packet.to_bytes(), addr) {
                        Ok(_) => {}
                        Err(_) => {
                            println!("We failed to send a packet!?")
                        }
                    };

                    // Don't bother checking if an ACK packet is still in transit
                    if packet.is_ack() {
                        continue;
                    }

                    // We need to keep track of which packets are currently in transit
                    // so we can accept acknowledgements for them later
                    in_transit.lock().unwrap().insert(
                        packet.get_sequence_number(),
                        TimeoutPacket {
                            send_time: SystemTime::now(),
                            packet,
                        },
                    );
                }
            }
        });
    }

    pub fn start_timeout_monitor_thread(&self) {
        let sending_queue = self.sending_queue.clone();
        let in_transit = self.in_transit.clone();

        thread::spawn(move || loop {
            {
                let mut in_transit = in_transit.lock().unwrap();
                let items = in_transit.drain_filter(|_key, val| {
                    SystemTime::now().duration_since(val.send_time).unwrap()
                        > RETRANSMISSION_TIMEOUT
                });

                for item in items.into_iter() {
                    println!("Packet has timed out: {:?}", item.1.packet);
                    sending_queue.lock().unwrap().push_back(item.1.packet);
                }
            }

            thread::sleep(RETRANSMISSION_TIMEOUT)
        });
    }

    pub fn verify_cookie(&self, cookie: &ConnectionCookie) -> bool {
        // TODO: Calculate MAC (Cookie Signature)

        if cookie.source_addr != self.addr {
            return false;
        }

        true
    }

    pub fn receive_packet(&mut self, packet: Packet) {
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
            self.send_ack(packet.get_sequence_number());
            self.insert_packet_incoming_queue(packet);
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

        self.set_connection_state(ConnectionState::Established);

        self.send_cookie_ack();
    }

    pub fn handle_cookie_ack(&mut self, packet: Packet) {
        self.handle_ack(&packet);
        self.set_connection_state(ConnectionState::Established);
    }

    pub fn handle_fin(&mut self, packet: Packet) {
        self.send_ack(packet.get_sequence_number());

        if self.get_connection_state() == ConnectionState::Established {
            self.set_connection_state(ConnectionState::CloseWait);

            return;
        }

        if self.get_connection_state() == ConnectionState::FinWait2 {
            self.set_connection_state(ConnectionState::TimeWait);

            return;
        }

        panic!("Invalid state when received fin");
    }

    pub fn handle_ack(&mut self, packet: &Packet) {
        self.in_transit
            .lock()
            .unwrap()
            .remove(&packet.get_ack_number());
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
        *seq_num += packet.payload_size();

        self.sending_queue.lock().unwrap().push_back(packet);
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
        let cookie = self.cookie.as_ref().unwrap();

        let mut flags = PacketFlags::new(0);
        flags.cookie = true;

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            cookie.to_bytes(),
        );

        self.send_packet(packet);

        self.set_connection_state(ConnectionState::CookieEchoed)
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
        let in_transit_count = self.in_transit.lock().unwrap().len();
        let to_send_count = self.sending_queue.lock().unwrap().len();

        in_transit_count == 0 && to_send_count == 0
    }

    pub fn wait_for_last_ack(&self) {
        while !self.connection_can_close() {}
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
