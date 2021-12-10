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
pub const MAX_BUFFER_SIZE: usize = 0; // Whats the maximum buffer we can have per connection and advertise.
pub const RETRANSMISSION_TIMEOUT: Duration = Duration::from_millis(100); // Timeout for retransmission in milliseconds

// According to the spec we would wait a whole 4 mins here.
// This seams fairly naive. Since we already need to calculate the RTT,
// a far better timeout period would be RTT + RETRANSMISSION_TIMEOUT.
// This would be the maximum time it would take for the other peer to retransmit an ack if our fin was lost.
pub const TIME_WAIT_TIMEOUT: Duration = Duration::from_secs(1);
