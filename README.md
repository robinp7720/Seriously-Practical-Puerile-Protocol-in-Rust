# Seriously Practical Puerile Protocol (SPPP)

This is an implementation of a protocol designed during a university module.
In it's current state, it's capable of transmiting and receiving bitwise perfect streams over lossy communication channels. We measured a peak data rate of 12MB/s.

## Running example applications

As it is common for Rust, you need `cargo` to run the project.
Rust nightly is required.

Included example applications include: `echo_client, echo_server, movie_client, movie_server`.
Run them with `cargo run --bin <example_name>`.

## Unit and integration tests

`cargo test` runs all unit and integration tests.

Unit tests exist for packet parsing and packet serialization,
sending and receiving a single data packet,
and sending and receiving multiple data packets.
It is also tested that 2 + 2 = 4. For some reason this example test was never removed.

## Project structure

`connection.rs` handles the connection state and packet ordering.


`connection_reliability_sender.rs` handles the everything related to the
actual sending of packets.
This includes flow control, retransmission, and congestion control.


`connection_security.rs` handles the signing, encryption and decryption of packets.


`packet.rs` handles the packet structure.

`cookie.rs` handles the cookie structure as well as the HMAC calculation.
