FROM ghcr.io/rust-lang/rust:nightly

RUN apt-get update
RUN apt-get install iproute2 libssl-dev -y

WORKDIR /sppp/

ENV CARGO_HOME=/.cargo

# Copy the entire prokject files
COPY . .

# This file will emulate a real life internet connection on the loopback interface
COPY ./tests/realistic_network/configure_interface.sh .

# Use this cetrificate instead of the defualt
COPY ./certificates/DO_NOT_USE.key ./certificates/server.key
COPY ./certificates/DO_NOT_USE.crt ./certificates/server.crt

RUN chmod +x ./configure_interface.sh

CMD ./configure_interface.sh; cargo test --release -- --nocapture