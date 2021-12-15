use rand::Rng;
use spppsocketredo::SPPPSocket;
use std::fmt::format;
use std::thread;

const IP: &str = "127.0.0.1";
const PORT: u16 = 2060;

// TODO: increase this number when congestion control is active
const STRING_SIZE: usize = 1_000;

///
/// Send a big amount of data to the server and check if it is received correctly
///
#[test]
fn big_load_integration() {
    let to_send: String = generate_long_random_string(STRING_SIZE);
    let to_receive = to_send.clone();

    let client = thread::Builder::new()
        .name("Client".to_string())
        .spawn(move || client(to_send))
        .unwrap();

    let server = thread::Builder::new()
        .name("Server".to_string())
        .spawn(move || server(to_receive.as_bytes()))
        .unwrap();

    // keep main thread alive while test is running
    server.join();
    client.join();
}

fn client(message: String) {
    let mut socket = SPPPSocket::new(None);
    let mut con = socket.connect(format!("{}:{}", IP, PORT)).unwrap();

    con.send(Vec::from(message.as_bytes()));
}

fn server(message: &[u8]) {
    let socket = SPPPSocket::new(Some(PORT));

    let mut connection = socket.accept().unwrap();

    let mut buf: Vec<u8> = Vec::new();

    loop {
        let mut data = connection.recv().unwrap();

        buf.append(&mut data);

        if buf.len() >= message.len() {
            assert_eq!(&buf, message);

            return;
        }
    }
}

fn generate_long_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";
    let mut rng = rand::thread_rng();

    let long_string: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0, CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    long_string
}
