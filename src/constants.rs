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
pub const INITIAL_RETRANSMISSION_TIMEOUT: Duration = Duration::from_millis(2000); // Timeout for retransmission in milliseconds

// According to the spec we would wait a whole 4 mins here.
// This seams fairly naive. Since we already need to calculate the RTT,
// a far better timeout period would be RTT + RETRANSMISSION_TIMEOUT.
// This would be the maximum time it would take for the other peer to retransmit an ack if our fin was lost.
pub const TIME_WAIT_TIMEOUT: Duration = Duration::from_secs(240);

// There is no explanation as to why this exists in the RFC.
// According to Christopher Zeise, it's to make sure that the timeout for an ack is above
// the minimum we can actually wait.
// It's completely useless for that though.
// And since Thread::sleep() already rounds up to the next best time we can wait,
// we don't actually need this.
pub const CLOCK_GRANULARITY: Duration = Duration::from_secs(2);

// The receive window size in amount packets
pub const RECEIVE_WINDOW_SIZE: u16 = 1000;

pub const DIFFIE_HELLMAN_GENERATOR: u16 = 2;

pub const DIFFIE_HELLMAN_PRIME: [u8; 256] = hex!(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
);
