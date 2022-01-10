use spppsocketredo::SPPPSocket;
use std::str::from_utf8;
use std::thread;

fn main() {
    let socket = SPPPSocket::new(Some(2030));

    let mut connection = socket.accept().unwrap();
    connection.send(vec![0; 10]);

    let handle = thread::spawn(move || loop {
        let data = connection.recv().unwrap();

        println!("New Data: {:?}", data);

        if data == vec![0, 0, 1] {
            return;
        }
    });

    handle.join();
}
