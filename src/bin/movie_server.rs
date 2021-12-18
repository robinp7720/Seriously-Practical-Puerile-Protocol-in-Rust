use spppsocketredo::SPPPSocket;
use std::fs::File;
use std::io::{Read, Write};
use std::thread;
use std::time::Duration;

fn main() {
    let socket = SPPPSocket::new(Some(2031));
    let chunk_size = 1200;

    loop {
        let mut connection = socket.accept().unwrap();

        thread::spawn(move || {
            let mut file =
                File::open("/home/robin/Free.Guy.2021.1080p.HDRip.X264-EVO.mkv").unwrap();
            loop {
                let mut chunk = vec![0; chunk_size];
                let mut amt = file.read_exact(&mut chunk).unwrap();

                connection.send(chunk);

                if connection.client_closed() {
                    eprintln!("Client has closed the connection");
                    return;
                }

                //thread::sleep(Duration::from_millis(20));
            }
        });
    }
}
