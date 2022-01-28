use std::fs::File;
use std::io::Read;
use std::thread;

use spppsocketredo::SPPPSocket;

fn main() {
    let socket = SPPPSocket::new(Some(2031), true);
    let chunk_size = 1200;

    loop {
        let connection = socket.accept().unwrap();

        thread::spawn(move || {
            let mut file =
                File::open("/home/robin/Free.Guy.2021.1080p.HDRip.X264-EVO.mkv").unwrap();
            loop {
                let mut chunk = vec![0; chunk_size];

                match file.read_exact(&mut chunk) {
                    Ok(_) => {}
                    Err(_) => return,
                };

                connection.send(chunk);

                if connection.client_closed() {
                    eprintln!("Client has closed the connection");
                    return;
                }
            }
        });
    }
}
