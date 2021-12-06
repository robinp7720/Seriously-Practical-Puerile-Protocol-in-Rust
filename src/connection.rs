use crate::connection::ConnectionState::CookieWait;
use crate::constants::MAX_PAYLOAD_SIZE;
use crate::cookie::ConnectionCookie;
use crate::packet::{Packet, PacketFlags, PrimaryHeader};
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Mutex;

enum ConnectionState {
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
    incoming: Mutex<Vec<Packet>>,
    sending_queue: Mutex<Vec<Vec<u8>>>,
    connection_state: ConnectionState,
    cookie: Option<ConnectionCookie>,
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
            incoming: Mutex::new(vec![]),
            sending_queue: Mutex::new(vec![]),
            connection_state: ConnectionState::CookieWait,
            cookie,
        }
    }

    pub fn verify_cookie(&self, cookie: &ConnectionCookie) -> bool {
        // TODO: Calculate MAC (Cookie Signature)

        if cookie.source_addr != self.addr {
            return false;
        }

        true
    }

    pub fn receive_packet(&mut self, packet: Packet) {
        // If we receive a cookie-echo, we need to verify it and respond with an ack
        if packet.is_cookie() && !packet.is_ack() {
            self.handle_cookie_echo(packet);

            return;
        }

        let mut incoming = self.incoming.lock().unwrap();

        incoming.push(packet);
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

        self.connection_state = ConnectionState::Established;

        self.send_cookie_ack();
    }

    pub fn canRecv(&self) -> bool {
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

    fn send_packet(&self, packet: Packet) {
        self.socket.send_to(&*packet.to_bytes(), self.addr);
    }

    pub fn send_data(&self, payload: Vec<u8>) {
        self.append_to_send_queue(payload);
    }

    fn append_to_send_queue(&self, payload: Vec<u8>) {
        let chunks: Vec<&[u8]> = payload.chunks(MAX_PAYLOAD_SIZE).collect();

        for chunk in chunks {
            println!("Sending to send queue: {:?}", chunk);
            self.sending_queue.lock().unwrap().push(Vec::from(chunk))
        }
    }

    pub fn process_send_queue() {
        // Get the first element of the send queue and send it to the client
    }

    pub fn create_packet_send_data(&self, payload: Vec<u8>) {
        let mut flags = PacketFlags::new(0);

        let packet = Packet::new(
            PrimaryHeader::new(self.connection_id, 0, 0, 0, flags),
            None,
            None,
            payload,
        );

        self.send_packet(packet);
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
        self.connection_state = ConnectionState::CookieEchoed;
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

    pub fn get_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn get_connection_id(&self) -> u32 {
        self.connection_id
    }

    pub fn receive(&self, packet: Packet) {}
}
