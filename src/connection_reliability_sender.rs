use std::cmp::{max, min};
use std::collections::HashMap;

//use cipher::generic_array::typenum::Or;
use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use crate::connection::PacketRetransmit;
use crate::connection_security::Security;

use crate::constants::{
    CLOCK_GRANULARITY, CONNECTION_IDLE_TIME, INITIAL_RETRANSMISSION_TIMEOUT, MAX_PACKET_SIZE,
    MAX_PAYLOAD_SIZE, MAX_RETRANSMIT_COUNT, RECEIVE_WINDOW_SIZE,
};
use crate::packet::{Packet, SignatureHeader};

struct TimeoutPacket {
    send_time: SystemTime,
    packet: PacketWithRetransmit,
    timeout: Duration,
}

struct PacketWithRetransmit {
    packet: Packet,
    retransmit: i8,
}

struct TransitStatus {
    send_time: SystemTime,
    arrived: bool,
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum CongestionPhase {
    FastProbing,
    CongestionAvoidance,
}

pub struct CongestionHandler {
    cwnd: AtomicU64,
    congestion_phase: Mutex<CongestionPhase>,

    // any packet until this sequence number is part of any loss window and
    // another lost packet should not cause a reduction in the congestion window
    loss_til: Arc<AtomicU32>, // needs fix for wrap around case, works for now...

    // all sequence numbers which are in flight
    window: Mutex<VecDeque<u32>>,

    last_packet_send: Arc<Mutex<SystemTime>>,
}

impl CongestionHandler {
    pub fn cwnd_packet_loss(&self, seq_num: u32) {
        let window_lock = self.window.lock().unwrap();

        // last sequence number
        let x = match window_lock.back() {
            Some(seq_num) => *seq_num,
            _ => return,
        };

        // ignore packet when paket is already part of a loss window
        let loss_til = self.loss_til.load(Ordering::Relaxed);
        eprintln!("Packet loss, Losswindow til: {}", loss_til);
        if loss_til > ((RECEIVE_WINDOW_SIZE as usize * 10) * MAX_PAYLOAD_SIZE) as u32 {
            let threshold =
                loss_til as usize - ((RECEIVE_WINDOW_SIZE as usize * 10) * MAX_PAYLOAD_SIZE);
            if seq_num > threshold as u32 && seq_num < loss_til {
                return;
            }
        } else if seq_num < loss_til
            || seq_num as u64
                > 2_u64.pow(32) - ((RECEIVE_WINDOW_SIZE as usize * 10) * MAX_PAYLOAD_SIZE) as u64
        {
            return;
        }

        // update last lost packet
        self.loss_til.store(x, Ordering::Relaxed);

        // halve cwnd
        let cwnd = self
            .cwnd
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| {
                Some(self.halve_to_min(x))
            })
            .expect("Could not halve cwnd");
        eprintln!("New CWND: {}", cwnd);
        *self.congestion_phase.lock().unwrap() = CongestionPhase::CongestionAvoidance;
    }

    fn halve_to_min(&self, x: u64) -> u64 {
        let y = x / 2;
        if y > MAX_PACKET_SIZE as u64 {
            return y;
        }
        MAX_PACKET_SIZE as u64
    }

    pub fn get_congestion_phase(&self) -> CongestionPhase {
        *self.congestion_phase.lock().unwrap()
    }

    pub fn update_cwnd_ack(&self) {
        let congestion_phase = self.get_congestion_phase();
        match congestion_phase {
            CongestionPhase::FastProbing => self.increase_cwnd(MAX_PACKET_SIZE as u64),
            CongestionPhase::CongestionAvoidance => {
                let curr_cwnd = self.get_cwnd();
                self.increase_cwnd(((MAX_PACKET_SIZE * MAX_PACKET_SIZE) as u64) / curr_cwnd);
            }
        }
    }

    pub fn get_cwnd(&self) -> u64 {
        self.cwnd.load(Ordering::Relaxed)
    }

    pub fn increase_cwnd(&self, num_bytes: u64) {
        if self.get_cwnd() < 2_u64.pow(32) + MAX_PACKET_SIZE as u64 {
            self.cwnd.fetch_add(num_bytes, Ordering::Relaxed);
        }
    }

    fn remove_from_window(&self, seq_num: u32) {
        let mut window_lock = self.window.lock().unwrap();
        // Debug print: eprintln!("Wnd: {:?}", window_lock);
        window_lock.retain(|x| *x != seq_num);
    }

    pub fn append_to_window(&self, seq_num: u32) {
        let mut window_lock = self.window.lock().unwrap();
        if !window_lock.contains(&seq_num) {
            window_lock.push_back(seq_num);
        }
    }
}

pub struct ConnectionReliabilitySender {
    in_transit: Arc<Mutex<HashMap<PacketRetransmit, TransitStatus>>>,

    sending_queue_tx: Sender<PacketWithRetransmit>,

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
    flow_sender_tx: Sender<PacketWithRetransmit>,
    queued_for_flight: Arc<AtomicU16>,

    // track congestion control
    congestion_handler: Arc<CongestionHandler>,
}

impl ConnectionReliabilitySender {
    pub fn new(
        addr: Arc<RwLock<SocketAddr>>,
        socket: UdpSocket,
        security: Arc<RwLock<Security>>,
    ) -> Self {
        let in_transit = Arc::new(Mutex::new(HashMap::new()));

        let (sending_queue_tx, sending_queue_rx) = channel::<PacketWithRetransmit>();
        let (in_transit_queue_tx, in_transit_queue_rx) = channel::<TimeoutPacket>();
        let (flow_sender_tx, flow_sender_rx) = channel::<PacketWithRetransmit>();

        let curr_rto = Arc::new(AtomicU64::new(
            INITIAL_RETRANSMISSION_TIMEOUT.as_millis() as u64
        ));

        let local_arwnd = Arc::new(AtomicU16::new(2));
        let remote_arwnd = Arc::new(AtomicU16::new(2));
        let in_flight = Arc::new(AtomicU16::new(0));
        let queued_for_flight = Arc::new(AtomicU16::new(0));

        let congestion_handler = Arc::new(CongestionHandler {
            cwnd: AtomicU64::new(4 * MAX_PACKET_SIZE as u64),
            congestion_phase: Mutex::new(CongestionPhase::FastProbing),
            loss_til: Arc::new(AtomicU32::new(0)),
            window: Mutex::new(VecDeque::new()),
            last_packet_send: Arc::new(Mutex::new(SystemTime::now())),
        });

        Self::start_send_thread(
            sending_queue_rx,
            in_transit.clone(),
            in_transit_queue_tx,
            addr,
            socket.try_clone().unwrap(),
            curr_rto.clone(),
            local_arwnd.clone(),
            congestion_handler.clone(),
            security,
        );

        Self::start_timeout_monitor_thread(
            in_transit_queue_rx,
            sending_queue_tx.clone(),
            in_transit.clone(),
            congestion_handler.clone(),
        );

        let flow_thread_handle = Self::start_flow_thread(
            flow_sender_rx,
            sending_queue_tx.clone(),
            in_flight.clone(),
            remote_arwnd.clone(),
            queued_for_flight.clone(),
            congestion_handler.clone(),
        );

        ConnectionReliabilitySender {
            in_transit,
            sending_queue_tx,

            flow_sender_tx,

            flow_thread_handle,

            srtt: 0,
            rttvar: 0,
            curr_rto,

            in_flight,
            queued_for_flight,

            local_arwnd,
            remote_arwnd,

            congestion_handler,
        }
    }

    fn start_flow_thread(
        flow_send_rx: Receiver<PacketWithRetransmit>,
        sending_queue_tx: Sender<PacketWithRetransmit>,
        in_flight: Arc<AtomicU16>,
        remote_arwnd: Arc<AtomicU16>,
        queued_for_flight: Arc<AtomicU16>,
        congestion_handler: Arc<CongestionHandler>,
    ) -> JoinHandle<u8> {
        thread::spawn(move || loop {
            loop {
                if remote_arwnd.load(Ordering::Relaxed) > in_flight.load(Ordering::Relaxed)
                    && congestion_handler.cwnd.load(Ordering::Relaxed)
                        > ((in_flight.load(Ordering::Relaxed) as u64) * MAX_PACKET_SIZE as u64)
                            + MAX_PACKET_SIZE as u64
                {
                    let last_packet_sent = *congestion_handler.last_packet_send.lock().unwrap();

                    // detect idle timeout
                    if SystemTime::now().duration_since(last_packet_sent).unwrap()
                        > CONNECTION_IDLE_TIME
                    {
                        congestion_handler
                            .cwnd
                            .store(4 * MAX_PACKET_SIZE as u64, Ordering::Relaxed);

                        *congestion_handler.congestion_phase.lock().unwrap() =
                            CongestionPhase::FastProbing;
                    }
                    break;
                }

                thread::yield_now();
            }

            let packet = flow_send_rx.recv().unwrap();

            in_flight.fetch_add(1, Ordering::Relaxed);
            queued_for_flight.fetch_sub(1, Ordering::Relaxed);

            sending_queue_tx
                .send(packet)
                .expect("Could not send packet to sending queue");
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn start_send_thread(
        sending_queue_rx: Receiver<PacketWithRetransmit>,
        in_transit: Arc<Mutex<HashMap<PacketRetransmit, TransitStatus>>>,
        in_transit_queue: Sender<TimeoutPacket>,
        addr_container: Arc<RwLock<SocketAddr>>,
        socket: UdpSocket,
        curr_rto: Arc<AtomicU64>,
        arwnd: Arc<AtomicU16>,
        congestion_handler: Arc<CongestionHandler>,
        security: Arc<RwLock<Security>>,
    ) {
        thread::spawn(move || {
            loop {
                let mut packet = sending_queue_rx.recv().unwrap();

                let arwnd = arwnd.load(Ordering::Relaxed);

                packet.packet.set_arwnd(arwnd);

                *congestion_handler.last_packet_send.lock().unwrap() = SystemTime::now();

                let addr = *addr_container.read().unwrap();

                if !packet.packet.is_sec() && security.read().unwrap().is_encrypted() {
                    let signature = security
                        .read()
                        .unwrap()
                        .sign_packet(packet.packet.get_padded_packet().to_bytes());

                    if !signature.is_empty() {
                        packet
                            .packet
                            .set_signature_header(SignatureHeader::new(signature));
                    }
                }

                match socket.send_to(&*packet.packet.to_bytes(), addr) {
                    Ok(_) => {}
                    Err(_) => {
                        // Maybe it would be good if we handled packet failure differently if it
                        // failed on our end.
                        // But really it doesn't change that much.
                        // If we failed to send a packet, we can just let the timeout handle it instead.
                        eprintln!("Sending a packet to the UDP socket failed")
                    }
                };

                // Don't bother checking if an ACK packet is still in transit
                // This should handle cookie ACKs as well since they dont have a payload and have
                // the ack flag set.
                if packet.packet.is_ack() {
                    continue;
                }

                // We need to keep track of which packets are currently in transit
                // so we can accept acknowledgements for them later
                let mut packet_classification =
                    PacketRetransmit::Data(packet.packet.get_sequence_number());

                if packet.packet.is_init() {
                    packet_classification = PacketRetransmit::Init;
                } else if packet.packet.is_cookie() {
                    packet_classification = PacketRetransmit::CookieEcho;
                } else if packet.packet.is_arwnd() {
                    packet_classification =
                        PacketRetransmit::ArwndUpdate(packet.packet.get_sequence_number());
                }

                let send_time = SystemTime::now();

                congestion_handler.append_to_window(packet.packet.get_sequence_number());

                in_transit.lock().unwrap().insert(
                    packet_classification,
                    TransitStatus {
                        send_time,
                        arrived: false,
                    },
                );

                in_transit_queue
                    .send(TimeoutPacket {
                        send_time,
                        packet,
                        timeout: Duration::from_millis(curr_rto.load(Ordering::Relaxed)),
                    })
                    .expect("Colud not send packet to timeout handler");
            }
        });
    }

    fn start_timeout_monitor_thread(
        transit_queue_rx: Receiver<TimeoutPacket>,
        sending_queue_tx: Sender<PacketWithRetransmit>,
        in_transit: Arc<Mutex<HashMap<PacketRetransmit, TransitStatus>>>,
        congestion_handler: Arc<CongestionHandler>,
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
                PacketRetransmit::Data(current_timeout_packet.packet.packet.get_sequence_number());

            if current_timeout_packet.packet.packet.is_init() {
                packet_classification = PacketRetransmit::Init;
            }

            if current_timeout_packet.packet.packet.is_cookie() {
                packet_classification = PacketRetransmit::CookieEcho;
            }

            if current_timeout_packet.packet.packet.is_arwnd() {
                packet_classification = PacketRetransmit::ArwndUpdate(
                    current_timeout_packet.packet.packet.get_sequence_number(),
                );
            }

            let transit_status = match in_transit.lock().unwrap().remove(&packet_classification) {
                None => continue,
                Some(status) => status,
            };

            if current_timeout_packet.packet.retransmit >= MAX_RETRANSMIT_COUNT {
                panic!("A packet exceeded the max retransmit count.");
                // !TODO: Implement a function to close the connection
            }

            if !transit_status.arrived {
                congestion_handler
                    .cwnd_packet_loss(current_timeout_packet.packet.packet.get_sequence_number());
                sending_queue_tx
                    .send(PacketWithRetransmit {
                        packet: current_timeout_packet.packet.packet,
                        retransmit: current_timeout_packet.packet.retransmit + 1,
                    })
                    .expect("Could not send packet to sending queue for retransmit");
            }
        });
    }

    pub fn send_packet(&mut self, packet: Packet) {
        if packet.is_ack() || packet.is_arwnd() {
            // Don't bother with flow control for ACKs
            self.sending_queue_tx
                .send(PacketWithRetransmit {
                    packet,
                    retransmit: 0,
                })
                .expect("Could not send packet to sending queue");
            return;
        }

        self.queued_for_flight.fetch_add(1, Ordering::Relaxed);

        self.flow_sender_tx
            .send(PacketWithRetransmit {
                packet,
                retransmit: 0,
            })
            .expect("Could not push packet to flow sender queue");
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

        if packet.is_arwnd() {
            packet_classification = PacketRetransmit::ArwndUpdate(packet.get_ack_number());
        }

        let (duplicate, send_time) = {
            let mut in_transit_lock = self.in_transit.lock().unwrap();

            let transit_status = match in_transit_lock.get_mut(&packet_classification) {
                None => {
                    //while self.congestion_handler.window_flag.load(Ordering::Relaxed) {}
                    self.congestion_handler
                        .remove_from_window(packet.get_ack_number());
                    return;
                }
                Some(transit_status) => transit_status,
            };

            let duplicate = transit_status.arrived;

            transit_status.arrived = true;

            (duplicate, transit_status.send_time)
        };

        self.congestion_handler
            .remove_from_window(packet.get_ack_number());

        if !duplicate {
            self.update_rtt(send_time);
            self.congestion_handler.update_cwnd_ack();

            if !packet.is_arwnd() {
                self.in_flight.fetch_sub(1, Ordering::Relaxed);
            }
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
        let _in_flight = self.in_flight.load(Ordering::Relaxed) as u64;
        let queued = self.queued_for_flight.load(Ordering::Relaxed) as u64;

        remote_arwnd > queued
    }
}
