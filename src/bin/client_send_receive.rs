use std::fs::File;
use std::io::{Read, Write};

use spppsocketredo::SPPPSocket;

fn main() {
    let mut socket = SPPPSocket::new(None, true);
    let chunk_size = 1200;

    let mut connection = socket.connect("81.169.201.84:2031").unwrap();

    let mut file = File::open("/home/robin/Free.Guy.2021.1080p.HDRip.X264-EVO.mkv").unwrap();

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();

    loop {
        let mut chunk = vec![0; chunk_size];
        match file.read_exact(&mut chunk) {
            Ok(_) => {}
            Err(_) => return,
        };

        connection.send(chunk);

        while connection.can_recv() {
            let data = connection.recv().unwrap();
            match handle.write_all(&*data) {
                Ok(_) => {}
                Err(_) => return,
            };
        }

        if connection.client_closed() {
            eprintln!("Client has closed the connection");
            return;
        }
    }
}
