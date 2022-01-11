use crate::connection::PacketRetransmit;
use crate::connection_reliability_sender::CongestionPhase::{CongestionAvoidance, FastProbing};
use crate::constants::{
    CLOCK_GRANULARITY, INITIAL_RETRANSMISSION_TIMEOUT, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE,
    RECEIVE_WINDOW_SIZE,
};
use crate::packet::Packet;
use std::cmp::{max, min};
use std::collections::HashMap;
use std::mem::{swap, take};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

struct ReliabilitySenderThreadStop {
    join_handle: Option<JoinHandle<usize>>,
    send_channel: Sender<usize>, // any message send in this channel signals the thread to terminate
}

struct TimeoutPacket {
    send_time: SystemTime,
    packet: Packet,
    timeout: Duration,
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
}

impl CongestionHandler {
    pub fn cwnd_packet_loss(&self) {
        self.cwnd
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| {
                Some(self.halve_to_min(x))
            });
        *self.congestion_phase.lock().unwrap() = CongestionPhase::CongestionAvoidance;
    }

    fn halve_to_min(&self, x: u64) -> u64 {
        let y = x / 2;
        if y > 4 * MAX_PACKET_SIZE as u64 {
            return y;
        }
        return 4 * MAX_PACKET_SIZE as u64;
    }

    pub fn get_congestion_phase(&self) -> CongestionPhase {
        *self.congestion_phase.lock().unwrap()
    }

    pub fn get_cwnd(&self) -> u64 {
        self.cwnd.load(Ordering::Relaxed)
    }

    pub fn increase_cwnd(&self, num_bytes: u64) {
        if self.get_cwnd() < 2_u64.pow(32) + MAX_PACKET_SIZE as u64 {
            self.cwnd.fetch_add(num_bytes, Ordering::Relaxed);
        }
    }
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

    // channel and join handle to all threads
    threads: Vec<ReliabilitySenderThreadStop>,

    // Available receive window in packets
    local_arwnd: Arc<AtomicU16>,
    remote_arwnd: Arc<AtomicU16>,
    flow_thread_handle: JoinHandle<u8>,
    flow_sender_tx: Sender<Packet>,
    queued_for_flight: Arc<AtomicU16>,

    // track congestion window
    congestion_handler: Arc<CongestionHandler>,
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

        let congestion_handler = Arc::new(CongestionHandler {
            cwnd: AtomicU64::new(4 * MAX_PACKET_SIZE as u64),
            congestion_phase: Mutex::new(CongestionPhase::FastProbing),
        });

        let send_thread_channel: (Sender<usize>, Receiver<usize>) = mpsc::channel();
        let send_thread_join_handle = Self::start_send_thread(
            sending_queue_rx,
            in_transit.clone(),
            in_transit_queue_tx.clone(),
            addr.clone(),
            socket.try_clone().unwrap(),
            curr_rto.clone(),
            local_arwnd.clone(),
            send_thread_channel.1,
        );

        let timeout_monitor_thread_channel: (Sender<usize>, Receiver<usize>) = mpsc::channel();
        let timeout_monitor_join_handle = Self::start_timeout_monitor_thread(
            in_transit_queue_rx,
            sending_queue_tx.clone(),
            in_transit.clone(),
            congestion_handler.clone(),
            timeout_monitor_thread_channel.1,
        );

        let flow_thread_channel: (Sender<usize>, Receiver<usize>) = mpsc::channel();
        let flow_thread_handle = Self::start_flow_thread(
            flow_sender_rx,
            sending_queue_tx.clone(),
            in_flight.clone(),
            remote_arwnd.clone(),
            queued_for_flight.clone(),
            congestion_handler.clone(),
            flow_thread_channel.1,
        );

        ConnectionReliabilitySender {
            in_transit,
            in_transit_queue_tx,
            sending_queue_tx,

            flow_sender_tx,

            flow_thread_handle,

            threads: vec![
                ReliabilitySenderThreadStop {
                    join_handle: Some(send_thread_join_handle),
                    send_channel: send_thread_channel.0,
                },
                ReliabilitySenderThreadStop {
                    join_handle: Some(timeout_monitor_join_handle),
                    send_channel: timeout_monitor_thread_channel.0,
                },
                ReliabilitySenderThreadStop {
                    join_handle: None,
                    send_channel: flow_thread_channel.0,
                },
            ],

            socket,
            addr,

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
        flow_send_rx: Receiver<Packet>,
        sending_queue_tx: Sender<Packet>,
        in_flight: Arc<AtomicU16>,
        remote_arwnd: Arc<AtomicU16>,
        queued_for_flight: Arc<AtomicU16>,
        congestion_handler: Arc<CongestionHandler>,
        thread_stop_receiver: Receiver<usize>,
    ) -> JoinHandle<u8> {
        thread::spawn(move || loop {
            loop {
                if remote_arwnd.load(Ordering::Relaxed) > in_flight.load(Ordering::Relaxed)
                    && congestion_handler.cwnd.load(Ordering::Relaxed)
                        > ((in_flight.load(Ordering::Relaxed) as u64) * MAX_PACKET_SIZE as u64)
                            + MAX_PACKET_SIZE as u64
                {
                    break;
                }

                thread::park();

                if thread_stop_receiver.try_recv().is_ok() {
                    eprintln!("stopping flow thread");
                    return 0;
                }
            }

            while let packet = flow_send_rx.try_recv() {
                if thread_stop_receiver.try_recv().is_ok() {
                    eprintln!("stopping flow thread");
                    return 0;
                }

                if packet.is_ok() {
                    let packet = packet.unwrap();

                    in_flight.fetch_add(1, Ordering::Relaxed);
                    queued_for_flight.fetch_sub(1, Ordering::Relaxed);

                    sending_queue_tx.send(packet);
                }
            }
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
        thread_stop_receiver: Receiver<usize>,
    ) -> JoinHandle<usize> {
        thread::spawn(move || {
            loop {
                if thread_stop_receiver.try_recv().is_ok() {
                    eprintln!("Stopping send thread");
                    return 0;
                }

                let mut packet = sending_queue_rx.try_recv();

                if packet.is_err() {
                    continue;
                }

                let mut packet = packet.unwrap();

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
                // the ack flag set.
                if packet.is_ack() {
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
                } else if packet.is_arwnd() {
                    packet_classification =
                        PacketRetransmit::ArwndUpdate(packet.get_sequence_number());
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
        })
    }

    fn start_timeout_monitor_thread(
        transit_queue_rx: Receiver<TimeoutPacket>,
        sending_queue_tx: Sender<Packet>,
        in_transit: Arc<Mutex<HashMap<PacketRetransmit, TransitStatus>>>,
        mut congestion_handler: Arc<CongestionHandler>,
        thread_stop_receiver: Receiver<usize>,
    ) -> JoinHandle<usize> {
        thread::spawn(move || loop {
            if thread_stop_receiver.try_recv().is_ok() {
                eprintln!("Stopping timeout monitor thread");
                return 0;
            }

            let current_timeout_packet = transit_queue_rx.try_recv();

            if current_timeout_packet.is_err() {
                continue;
            }

            let current_timeout_packet = current_timeout_packet.unwrap();

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

            if current_timeout_packet.packet.is_arwnd() {
                packet_classification = PacketRetransmit::ArwndUpdate(
                    current_timeout_packet.packet.get_sequence_number(),
                );
            }

            let transit_status = match in_transit.lock().unwrap().remove(&packet_classification) {
                None => continue,
                Some(status) => status,
            };

            if !transit_status.arrived {
                sending_queue_tx.send(current_timeout_packet.packet);
                congestion_handler.cwnd_packet_loss();
            }
        })
    }

    pub fn send_packet(&mut self, packet: Packet) {
        if packet.is_ack() || packet.is_arwnd() {
            // Don't bother with flow control for ACKs
            self.sending_queue_tx.send(packet);
            return;
        }

        self.queued_for_flight.fetch_add(1, Ordering::Relaxed);

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

        if packet.is_arwnd() {
            packet_classification = PacketRetransmit::ArwndUpdate(packet.get_sequence_number());
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
            self.update_cwnd_ack();

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

    //unused, consider removing
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

    pub fn update_cwnd_ack(&mut self) {
        if self.congestion_handler.get_congestion_phase() == CongestionPhase::FastProbing {
            self.congestion_handler
                .increase_cwnd(MAX_PACKET_SIZE as u64);
        }
        if self.congestion_handler.get_congestion_phase() == CongestionPhase::CongestionAvoidance {
            let curr_cwnd = self.congestion_handler.get_cwnd();
            self.congestion_handler
                .increase_cwnd(((MAX_PACKET_SIZE * MAX_PACKET_SIZE) as u64) / curr_cwnd);
        }
    }

    // Handle change in cwnd when loss is detected
    //pub fn congestion_loss(&mut self) {
    //    !ToDo();
    //}

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

impl Drop for ConnectionReliabilitySender {
    fn drop(&mut self) {
        while let Some(mut thread) = self.threads.pop() {
            thread.send_channel.send(0);
            if thread.join_handle.is_some() {
                let mut t = thread.join_handle.unwrap();
                t.join().expect("Could not join thread");
            }
        }

        let mut flow_thread_handle = thread::spawn(|| 0);
        swap(&mut flow_thread_handle, &mut self.flow_thread_handle);

        flow_thread_handle.thread().unpark();
        flow_thread_handle.join().expect("Could not join thread");

        eprintln!("Reliability sender dropped");
    }
}
