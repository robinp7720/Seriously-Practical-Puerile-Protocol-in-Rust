use crate::connection::PacketRetransmit;
use crate::constants::{
    CLOCK_GRANULARITY, INITIAL_RETRANSMISSION_TIMEOUT, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE,
    RECEIVE_WINDOW_SIZE,
};
use crate::packet::Packet;
use std::cmp::{max, min};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

struct TimeoutPacket {
    send_time: SystemTime,
    packet: Packet,
    timeout: Duration,
}

struct TransitStatus {
    send_time: SystemTime,
    arrived: bool,
}

pub struct ConnectionReliabilitySender {
    in_transit: Arc<Mutex<HashMap<PacketRetransmit, TransitStatus>>>,
    in_transit_queue_tx: Sender<TimeoutPacket>,
    socket: UdpSocket,
    addr: SocketAddr,
    sending_queue_tx: Sender<Packet>,

    // Smoothed Round Trip Time in milliseconds
    srtt: u128,

    // Round Trip Time Variation
    rttvar: u128,

    curr_rto: Arc<AtomicU64>,

    in_flight: Arc<AtomicU16>,

    // Available receive window in packets
    local_arwnd: Arc<AtomicU16>,
    remote_arwnd: Arc<AtomicU16>,
    flow_thread_handle: JoinHandle<u8>,
    flow_sender_tx: Sender<Packet>,
    queued_for_flight: Arc<AtomicU16>,
}

impl ConnectionReliabilitySender {
    pub fn new(addr: SocketAddr, socket: UdpSocket) -> Self {
        let in_transit = Arc::new(Mutex::new(HashMap::new()));

        let (sending_queue_tx, sending_queue_rx) = channel::<Packet>();
        let (in_transit_queue_tx, in_transit_queue_rx) = channel::<TimeoutPacket>();
        let (flow_sender_tx, flow_sender_rx) = channel::<Packet>();

        let curr_rto = Arc::new(AtomicU64::new(
            INITIAL_RETRANSMISSION_TIMEOUT.as_millis() as u64
        ));

        let local_arwnd = Arc::new(AtomicU16::new(2));
        let remote_arwnd = Arc::new(AtomicU16::new(2));
        let in_flight = Arc::new(AtomicU16::new(0));
        let queued_for_flight = Arc::new(AtomicU16::new(0));

        Self::start_send_thread(
            sending_queue_rx,
            in_transit.clone(),
            in_transit_queue_tx.clone(),
            addr.clone(),
            socket.try_clone().unwrap(),
            curr_rto.clone(),
            local_arwnd.clone(),
        );

        Self::start_timeout_monitor_thread(
            in_transit_queue_rx,
            sending_queue_tx.clone(),
            in_transit.clone(),
        );

        let flow_thread_handle = Self::start_flow_thread(
            flow_sender_rx,
            sending_queue_tx.clone(),
            in_flight.clone(),
            remote_arwnd.clone(),
            queued_for_flight.clone(),
        );

        ConnectionReliabilitySender {
            in_transit,
            in_transit_queue_tx,
            sending_queue_tx,

            flow_sender_tx,

            flow_thread_handle,

            socket,
            addr,

            srtt: 0,
            rttvar: 0,
            curr_rto,

            in_flight,
            queued_for_flight,

            local_arwnd,
            remote_arwnd,
        }
    }

    fn start_flow_thread(
        flow_send_rx: Receiver<Packet>,
        sending_queue_tx: Sender<Packet>,
        in_flight: Arc<AtomicU16>,
        remote_arwnd: Arc<AtomicU16>,
        queued_for_flight: Arc<AtomicU16>,
    ) -> JoinHandle<u8> {
        thread::spawn(move || loop {
            loop {
                if remote_arwnd.load(Ordering::Relaxed) > in_flight.load(Ordering::Relaxed) {
                    eprintln!("Adding a packet to the send queue");
                    break;
                }
                thread::park();
            }

            let packet = flow_send_rx.recv().unwrap();

            in_flight.fetch_add(1, Ordering::Relaxed);
            queued_for_flight.fetch_sub(1, Ordering::Relaxed);
            sending_queue_tx.send(packet);
        })
    }

    fn start_send_thread(
        sending_queue_rx: Receiver<Packet>,
        in_transit: Arc<Mutex<HashMap<PacketRetransmit, TransitStatus>>>,
        in_transit_queue: Sender<TimeoutPacket>,
        addr: SocketAddr,
        socket: UdpSocket,
        curr_rto: Arc<AtomicU64>,
        arwnd: Arc<AtomicU16>,
    ) {
        thread::spawn(move || {
            loop {
                let mut packet = sending_queue_rx.recv().unwrap();

                thread::sleep(Duration::from_micros(50));

                let arwnd = arwnd.load(Ordering::Relaxed);

                packet.set_arwnd(arwnd);

                match socket.send_to(&*packet.to_bytes(), addr) {
                    Ok(_) => {}
                    Err(_) => {
                        // Maybe it would be good if we handled packet failure differently if it
                        // failed on our end.
                        // But really it doesn't change that much.
                        // IF we failed to send a packet, we can just let the timeout handle it instead.
                        eprintln!("Sending a packet to the UDP socket failed")
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

                let send_time = SystemTime::now();

                in_transit.lock().unwrap().insert(
                    packet_classification,
                    TransitStatus {
                        send_time: send_time.clone(),
                        arrived: false,
                    },
                );

                in_transit_queue.send(TimeoutPacket {
                    send_time,
                    packet,
                    timeout: Duration::from_millis(curr_rto.load(Ordering::Relaxed)),
                });
            }
        });
    }

    fn start_timeout_monitor_thread(
        transit_queue_rx: Receiver<TimeoutPacket>,
        sending_queue_tx: Sender<Packet>,
        in_transit: Arc<Mutex<HashMap<PacketRetransmit, TransitStatus>>>,
    ) {
        thread::spawn(move || loop {
            let current_timeout_packet = transit_queue_rx.recv().unwrap();

            let deadline = current_timeout_packet.send_time + current_timeout_packet.timeout;
            let time_to_wait = match deadline.duration_since(SystemTime::now()) {
                Ok(time) => time,
                Err(_) => Duration::from_millis(0),
            };

            thread::sleep(time_to_wait);

            let mut packet_classification =
                PacketRetransmit::Data(current_timeout_packet.packet.get_sequence_number());

            if current_timeout_packet.packet.is_init() {
                packet_classification = PacketRetransmit::Init;
            }

            if current_timeout_packet.packet.is_cookie() {
                packet_classification = PacketRetransmit::CookieEcho;
            }

            let transit_status = in_transit
                .lock()
                .unwrap()
                .remove(&packet_classification)
                .unwrap();

            if !transit_status.arrived {
                eprintln!("Timeout: {:?}", current_timeout_packet.packet);
                sending_queue_tx.send(current_timeout_packet.packet);
            }
        });
    }

    pub fn send_packet(&mut self, packet: Packet) {
        eprintln!("Sending packet: {}", packet.get_sequence_number());

        let remote_arwnd = self.remote_arwnd.load(Ordering::Relaxed) as u64;

        eprintln!("rem arwnd locked");

        let in_flight = self.in_flight.load(Ordering::Relaxed) as u64;

        eprintln!("in flight locked");

        let queued = self.queued_for_flight.load(Ordering::Relaxed) as u64;

        eprintln!("queued locked");

        eprintln!(
            "Rem_arwnd: {}, in flight: {}, queued: {}",
            remote_arwnd, in_flight, queued
        );

        if packet.is_ack() {
            // Don't bother with flow control for ACKs
            self.sending_queue_tx.send(packet);
            return;
        }

        self.queued_for_flight.fetch_add(1, Ordering::Relaxed);
        //self.in_flight.fetch_add(1, Ordering::Relaxed);

        self.flow_sender_tx.send(packet);
    }

    /// Handle a received ack
    /// If a duplicate ack was received, returns true
    pub fn handle_ack(&mut self, packet: &Packet) {
        let mut packet_classification = PacketRetransmit::Data(packet.get_ack_number());

        if packet.is_init() {
            packet_classification = PacketRetransmit::Init;
        }

        if packet.is_cookie() {
            packet_classification = PacketRetransmit::CookieEcho;
        }

        let (duplicate, send_time) = {
            let mut in_transit_lock = self.in_transit.lock().unwrap();

            let transit_status = match in_transit_lock.get_mut(&packet_classification) {
                None => return,
                Some(transit_status) => transit_status,
            };

            let duplicate = transit_status.arrived;

            transit_status.arrived = true;

            (duplicate, transit_status.send_time.clone())
        };

        if !duplicate {
            self.update_rtt(send_time);
            self.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn update_rtt(&mut self, send_time: SystemTime) {
        let rtt = SystemTime::now()
            .duration_since(send_time)
            .unwrap()
            .as_millis();

        if self.srtt == 0 {
            // If this is the first time we are calculating the RTT,
            // we don't have any past values to use for calculating the variance.
            // Therefor, according to the spec, we should simply set the
            // smoothed round trip time to the first round trip time, and the variance
            // to half the rtt
            self.srtt = rtt;
            self.rttvar = rtt >> 1;
        } else {
            // 3/4 * rttvar + 1/4 * abs(srtt - rtt)
            // Bitshifts are used here because rust doesn't like using division with integers
            self.rttvar =
                ((3 * self.rttvar) >> 2) + ((max(self.srtt, rtt) - min(self.srtt, rtt)) >> 4);

            // 7/8 * srtt + 1/8 * rtt
            self.srtt = ((7 * self.srtt) >> 3) + (rtt >> 3);
        }

        self.curr_rto.store(
            (self.srtt + max(CLOCK_GRANULARITY.as_millis(), 4 * self.rttvar)) as u64,
            Ordering::Relaxed,
        );
    }

    pub fn get_in_flight(&self) -> u32 {
        (self.in_flight.load(Ordering::Relaxed) + self.queued_for_flight.load(Ordering::Relaxed))
            as u32
    }

    pub fn get_arwnd(&self) -> u16 {
        self.local_arwnd.load(Ordering::Relaxed)
    }

    pub fn update_local_arwnd(&self, buffer_size: usize) {
        let mut new_arwnd = 0;

        if RECEIVE_WINDOW_SIZE as usize * MAX_PAYLOAD_SIZE >= buffer_size {
            new_arwnd =
                (RECEIVE_WINDOW_SIZE as usize * MAX_PAYLOAD_SIZE - buffer_size) / MAX_PAYLOAD_SIZE
        }

        self.local_arwnd.store(new_arwnd as u16, Ordering::Relaxed);
    }

    pub fn update_remote_arwnd(&mut self, arwnd: u16) {
        self.remote_arwnd.store(arwnd, Ordering::Relaxed);
        self.flow_thread_handle.thread().unpark();
    }

    pub fn can_send(&self) -> bool {
        let remote_arwnd = self.remote_arwnd.load(Ordering::Relaxed) as u64;
        let in_flight = self.in_flight.load(Ordering::Relaxed) as u64;
        let queued = self.queued_for_flight.load(Ordering::Relaxed) as u64;

        /*println!(
            "Rem_arwnd: {}, in flight: {}, queued: {}",
            remote_arwnd, in_flight, queued
        );*/

        return remote_arwnd > queued;
    }
}
