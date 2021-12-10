use spppsocketredo::SPPPSocket;

fn main() {
    let mut socket = SPPPSocket::new(None);
    let mut con = socket.connect("127.0.0.1:2030").unwrap();

    let data = con.recv().unwrap();

    println!("We made it! {:?}", data);

    con.send(Vec::from([0, 0, 0]));
    con.send(Vec::from([0, 0, 1]));

    /*loop {
        let data = con.recv().unwrap();

        println!("We made it! {:?}", data);

        con.send(vec![0, 0, 0, 0, 3, 8, 7]);
    }*/
}
