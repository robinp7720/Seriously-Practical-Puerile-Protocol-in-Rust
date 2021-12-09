use spppsocketredo::SPPPSocket;
use std::thread;

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
    let mut socket = SPPPSocket::new(None);
    let mut con = socket.connect(format!("{}:{}", IP, PORT)).unwrap();

    let message = String::from("Hello, world!");
    con.send(Vec::from(message.as_bytes()));

    loop {
        if con.can_recv() {
            assert_eq!(message, String::from_utf8_lossy(&*con.recv().unwrap()));
            con.close();
            break;
        }
    }
}

fn server() {
    let socket = SPPPSocket::new(Some(PORT));

    loop {
        let mut connection = socket.accept().unwrap();

        thread::spawn(move || loop {
            let data = connection.recv().unwrap();
            connection.send(data);
            connection.close();
            break;
        });
    }
}
