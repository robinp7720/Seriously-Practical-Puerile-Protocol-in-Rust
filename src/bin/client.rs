use spppsocketredo::SPPPSocket;

fn main() {
    let mut socket = SPPPSocket::new(None);
    let mut con = socket.connect("127.0.0.1:2030").unwrap();

    let data = con.recv();

    println!("We made it! {:?}", data)
}
