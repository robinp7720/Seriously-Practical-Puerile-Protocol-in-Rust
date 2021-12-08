use spppsocketredo::SPPPSocket;

fn main() {
    let socket = SPPPSocket::new(Some(2030));

    //loop {
    let mut connection = socket.accept().unwrap();
    connection.send(vec![0; 10]);

    //loop {
    let data = connection.recv().unwrap();
    println!("data received: {:?}", data);

    //connection.close();
    //}
    //}
}
