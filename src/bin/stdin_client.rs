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

    let mut buffer = String::new();
    let mut stdin = io::stdin();

    println!("Establishing connection...");

    let mut socket = SPPPSocket::new(None);
    let mut con = socket.connect(format!("{}:{}", adresses, port)).unwrap();

    println!("Socket is open.");

    // raad from stdin and write it to socket
    let con_clone = con.clone();
    thread::spawn(move || loop {
        stdin.read_line(&mut buffer).unwrap();
        con_clone.send(Vec::from(buffer.as_bytes()));
    });

    // read from socket and print to stdout
    loop {
        if con.can_recv() {
            let data = con.recv().unwrap();
            println!("Got message: {:?}", data);
        }
    }
}
