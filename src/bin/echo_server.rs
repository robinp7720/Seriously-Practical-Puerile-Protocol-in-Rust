use spppsocketredo::SPPPSocket;
use std::thread;

fn main() {
    let socket = SPPPSocket::new(Some(2030), true);

    loop {
        let mut connection = socket.accept().unwrap();

        thread::spawn(move || loop {
            let data = connection.recv().unwrap();
            //println!("{:?}", data);
            connection.send(data);
        });
    }
}
