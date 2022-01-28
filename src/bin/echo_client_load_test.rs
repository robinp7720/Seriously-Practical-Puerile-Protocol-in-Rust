use rand::Rng;

use spppsocketredo::SPPPSocket;

fn generate_long_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";
    let mut rng = rand::thread_rng();

    let long_string: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    long_string
}

fn main() {
    let mut socket = SPPPSocket::new(None, true);
    let mut con = socket.connect("127.0.0.1:2030").unwrap();

    let mut size = 1;

    /*con.send(Vec::from([0, 0, 0]));
    con.send(Vec::from([0, 0, 1]));*/

    loop {
        println!("Sending data with size: {}", size);
        let payload = generate_long_random_string(size);
        let mut buf: Vec<u8> = Vec::new();
        con.send(Vec::from(payload.as_bytes()));
        while buf.len() < size {
            buf.append(&mut con.recv().unwrap());
        }

        let matching = buf
            .iter()
            .zip(payload.as_bytes())
            .filter(|&(a, b)| a == b)
            .count();

        if matching < size {
            println!("{}/{} bytes correct", matching, size);
        }

        size *= 2;
    }
}
