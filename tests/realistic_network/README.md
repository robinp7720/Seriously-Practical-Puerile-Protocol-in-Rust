# Network testing with docker

This docker container can be used to test the Transport protocol under real life conditions.
To do this, the container simulates several network conditions like latency, jitter and package lost.

## Run the container

To run the container you need a working docker demon.

Then execute the following commands:

1. `docker build -t sppp-test .`
2. `docker run -it --privileged sppp-test`

As an alternative to the second command you can also mount your `.cargo` folder to the docker container.
Doing so will make the execution way faster.

The following command will do so:
`docker run --rm -it -v ~/.cargo/registry/:/.cargo/registry --privileged sppp-test`

Doing this will execute the command `cargo test --release` inside the docker container.

Sadly the docker container needs to run in privileged mode.
This is caused by bridging the network interface in the docker  container.
