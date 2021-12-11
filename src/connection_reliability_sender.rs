use crate::connection::PacketRetransmit;
use crate::constants::RETRANSMISSION_TIMEOUT;
use crate::packet::Packet;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

struct TimeoutPacket {
    send_time: SystemTime,
    packet: Packet,
}

impl TimeoutPacket {
    pub fn timed_out(&self) -> bool {
        SystemTime::now().duration_since(self.send_time).unwrap() > RETRANSMISSION_TIMEOUT
    }
}

pub struct ConnectionReliabilitySender {
    in_transit: Arc<Mutex<HashMap<PacketRetransmit, bool>>>,
    in_transit_queue_tx: Sender<TimeoutPacket>,
    socket: UdpSocket,
    addr: SocketAddr,
    sending_queue_tx: Sender<Packet>,
}

impl ConnectionReliabilitySender {
    pub fn new(addr: SocketAddr, socket: UdpSocket) -> Self {
        let in_transit = Arc::new(Mutex::new(HashMap::new()));

        let (sending_queue_tx, sending_queue_rx) = channel::<Packet>();
        let (in_transit_queue_tx, in_transit_queue_rx) = channel::<TimeoutPacket>();

        Self::start_send_thread(
            sending_queue_rx,
            in_transit.clone(),
            in_transit_queue_tx.clone(),
            addr.clone(),
            socket.try_clone().unwrap(),
        );

        Self::start_timeout_monitor_thread(
            in_transit_queue_rx,
            sending_queue_tx.clone(),
            in_transit.clone(),
        );

        ConnectionReliabilitySender {
            in_transit,
            in_transit_queue_tx,
            sending_queue_tx,
            socket,
            addr,
        }
    }

    fn start_send_thread(
        sending_queue_rx: Receiver<Packet>,
        in_transit: Arc<Mutex<HashMap<PacketRetransmit, bool>>>,
        in_transit_queue: Sender<TimeoutPacket>,
        addr: SocketAddr,
        socket: UdpSocket,
    ) {
        thread::spawn(move || {
            loop {
                let packet = sending_queue_rx.recv().unwrap();

                match socket.send_to(&*packet.to_bytes(), addr) {
                    Ok(_) => {}
                    Err(_) => {
                        // Maybe it would be good if we handled packet failure differently if it
                        // failed on our end.
                        // But really it doesn't change that much.
                        // IF we failed to send a packet, we can just let the timeout handle it instead.
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

    fn start_timeout_monitor_thread(
        transit_queue_rx: Receiver<TimeoutPacket>,
        sending_queue_tx: Sender<Packet>,
        in_transit: Arc<Mutex<HashMap<PacketRetransmit, bool>>>,
    ) {
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

    pub fn send_packet(&self, packet: Packet) {
        self.sending_queue_tx.send(packet);
    }

    /// Handle a received ack
    /// If a duplicate ack was received, returns true
    pub fn handle_ack(&self, packet: &Packet) -> bool {
        let mut packet_classification = PacketRetransmit::Data(packet.get_ack_number());

        if packet.is_init() {
            packet_classification = PacketRetransmit::Init;
        }

        if packet.is_cookie() {
            packet_classification = PacketRetransmit::CookieEcho;
        }

        let mut in_transit_lock = self.in_transit.lock().unwrap();

        match in_transit_lock.insert(packet_classification, true) {
            None => true,
            Some(duplicate) => duplicate,
        }
    }
}
