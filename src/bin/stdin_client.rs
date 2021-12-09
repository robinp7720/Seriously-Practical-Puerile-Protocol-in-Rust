use spppsocketredo::SPPPSocket;
use std::io::Error;
use std::{env, io, thread};

///
/// Example Implementation of the SPPPSocket
///
/// call with  \[IP\] \[PORT\] as attributes of the binary
///
/// This implementation reads all text from stdin and sends it using the socket.
/// It also prints all incoming messages
///
fn main() {
    // read args
    let args: Vec<String> = env::args().collect();
    let adresses = &args[1];
    let port = &args[2];

    println!("Establishing connection...");

    let mut socket = SPPPSocket::new(None);
    let mut con = socket.connect(format!("{}:{}", adresses, port)).unwrap();

    println!("Socket is open.");

    let mut stdin = io::stdin();

    let con_clone = con.clone();
    // raad from stdin and write it to socket
    thread::spawn(move || loop {
        let mut buffer = String::new();
        stdin.read_line(&mut buffer).unwrap();
        con_clone.send(Vec::from(buffer.trim_end().as_bytes()));
    });

    // read from socket and print to stdout
    loop {
        if con.can_recv() {
            let data = con.recv().unwrap();
            println!("Got message: {}", String::from_utf8_lossy(&data));
        }
    }
}
