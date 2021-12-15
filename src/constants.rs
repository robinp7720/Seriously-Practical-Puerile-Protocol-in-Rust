use std::time::Duration;

pub const MAX_PAYLOAD_SIZE: usize = 1200;
pub const MAX_PRIMARY_HEADER_SIZE: usize = 128;
pub const MAX_CHANGE_KEY_HEADER_SIZE: usize = 64;
pub const MAX_SIGNATURE_HEADER_SIZE: usize = 64;
pub const MAX_ENCRYPTION_HEADER_SIZE: usize = 128 + 32;
pub const MAX_PACKET_SIZE: usize = MAX_PAYLOAD_SIZE
    + MAX_PRIMARY_HEADER_SIZE
    + MAX_CHANGE_KEY_HEADER_SIZE
    + MAX_SIGNATURE_HEADER_SIZE
    + MAX_ENCRYPTION_HEADER_SIZE;

// The retransmission timeout to be used before an RTT can be completed
pub const INITIAL_RETRANSMISSION_TIMEOUT: Duration = Duration::from_millis(100); // Timeout for retransmission in milliseconds

// According to the spec we would wait a whole 4 mins here.
// This seams fairly naive. Since we already need to calculate the RTT,
// a far better timeout period would be RTT + RETRANSMISSION_TIMEOUT.
// This would be the maximum time it would take for the other peer to retransmit an ack if our fin was lost.
pub const TIME_WAIT_TIMEOUT: Duration = Duration::from_secs(1);

// There is no explanation as to why this exists in the RFC.
// According to Christopher Zeise, it's to make sure that the timeout for an ack is above
// the minimum we can actually wait.
// It's completely useless for that though.
// And since Thread::sleep() already rounds up to the next best time we can wait,
// we don't actually need this.
pub const CLOCK_GRANULARITY: Duration = Duration::from_secs(2);

// The receive window size in amount packets
pub const RECEIVE_WINDOW_SIZE: u16 = 1000;
