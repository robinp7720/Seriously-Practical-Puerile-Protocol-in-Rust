use std::thread;

use spppsocketredo::SPPPSocket;

const IP: &str = "127.0.0.1";
const PORT: u16 = 2060;

///
/// This test checks if the protocol can send and receive packets
///
#[test]
fn echo_server_integration() {
    let client = thread::Builder::new()
        .name("Client".to_string())
        .spawn(client)
        .unwrap();

    let server = thread::Builder::new()
        .name("Server".to_string())
        .spawn(server)
        .unwrap();

    // keep main thread alive while test is running
    client.join();
}

fn client() {
    let mut socket = SPPPSocket::new(None, true);
    let mut con = socket.connect(format!("{}:{}", IP, PORT)).unwrap();

    let message = String::from("Hello, world!");
    con.send(Vec::from(message.as_bytes()));

    assert_eq!(message, String::from_utf8_lossy(&*con.recv().unwrap()));
    con.close();
}

fn server() {
    let socket = SPPPSocket::new(Some(PORT), true);

    loop {
        let mut connection = socket.accept().unwrap();

        thread::spawn(move || {
            let data = connection.recv().unwrap();
            connection.send(data);
            connection.close();
        });
    }
}
