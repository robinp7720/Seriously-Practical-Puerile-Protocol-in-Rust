use spppsocketredo::SPPPSocket;
use std::io::Write;

fn main() {
    let mut socket = SPPPSocket::new(None);
    let mut con = socket.connect("81.169.201.84:2031").unwrap();

    loop {
        let data = con.recv().unwrap();
        let mut stdout = std::io::stdout();
        let mut handle = stdout.lock();
        //con.send(Vec::from([0]));
        handle.write_all(&*data);
    }
}
