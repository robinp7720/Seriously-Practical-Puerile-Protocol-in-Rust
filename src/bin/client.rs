use spppsocketredo::SPPPSocket;

fn main() {
    let mut socket = SPPPSocket::new(None);
    socket.connect("127.0.0.1:2030");
}
