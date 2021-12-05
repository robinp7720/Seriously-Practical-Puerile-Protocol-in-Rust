use spppsocketredo::SPPPSocket;

fn main() {
    let mut socket = SPPPSocket::new(Some(2030));

    let connection = socket.accept();
}
