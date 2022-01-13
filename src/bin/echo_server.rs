use std::thread;

use spppsocketredo::SPPPSocket;

fn main() {
    let socket = SPPPSocket::new(Some(2030), true);

    loop {
        let mut connection = socket.accept().unwrap();

        thread::spawn(move || loop {
            let data = connection.recv().unwrap();
            println!("{}", std::str::from_utf8(&*data).unwrap());
            connection.send(data);
        });
    }
}
