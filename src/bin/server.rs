use spppsocketredo::SPPPSocket;

fn main() {
    let mut socket = SPPPSocket::new(Some(2030));

    loop {
        let connection = socket.accept().unwrap();
        connection.send(vec![0, 2, 3, 7]);
    }
}
