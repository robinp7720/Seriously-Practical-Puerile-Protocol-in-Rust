use std::io::Write;

use spppsocketredo::SPPPSocket;

fn main() {
    let mut socket = SPPPSocket::new(None, true);
    let mut con = socket.connect("81.169.201.84:2031").unwrap();

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();

    loop {
        let data = con.recv().unwrap();
        match handle.write_all(&*data) {
            Ok(_) => {}
            Err(_) => return,
        }
    }
}
