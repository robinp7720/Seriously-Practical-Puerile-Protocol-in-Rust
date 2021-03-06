use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::{io, thread};

use spppsocketredo::SPPPSocket;

// see here: https://stackoverflow.com/questions/30012995/how-can-i-read-non-blocking-from-stdin
fn create_stdin_channel() -> Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();

    thread::spawn(move || loop {
        let mut str_buffer = String::new();
        io::stdin().read_line(&mut str_buffer).unwrap();
        tx.send(str_buffer).unwrap();
    });

    rx
}

fn main() {
    let mut socket = SPPPSocket::new(None, true);
    let mut con = socket.connect("127.0.0.1:2030").unwrap();
    let receiver = create_stdin_channel();

    loop {
        if con.can_recv() {
            eprintln!("{}", std::str::from_utf8(&*con.recv().unwrap()).unwrap());
        }

        if let Ok(line) = receiver.try_recv() {
            eprintln!("{:?}", line.as_bytes());
            if line == "\n" {
                return;
            }

            con.send(line.as_bytes().to_vec());
        }
    }
}
