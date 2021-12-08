use spppsocketredo::SPPPSocket;
use std::str::from_utf8;
use std::thread;

fn main() {
    let socket = SPPPSocket::new(Some(2030));

    loop {
        let mut connection = socket.accept().unwrap();
        connection.send(vec![0; 10]);

        thread::spawn(move || loop {
            let data = connection.recv().unwrap();
            let message = from_utf8(&*data).unwrap();
            println!("data received: {}", message);

            if message == "close please!" {
                return;
            }
        });
    }
}
