ARG BUILDER_IMAGE=builder_cache

############################################################
# Cache image with all the deps
FROM rust:1.99-trixie@sha256:09027f873d45b8ecd1dc86f1fa13b7a62b875c961f017a0e331267b350430137 AS builder_cache

RUN rustup component add rustfmt clippy && apt-get update && apt-get install cmake libclang-dev -y

WORKDIR /build
COPY . ./


RUN cargo fmt --all -- --check --color=always || (echo "Use cargo fmt to format your code"; exit 1)
RUN cargo clippy --all -- -D warnings || (echo "Solve your clippy warnings to succeed"; exit 1)

#RUN cargo test --all --all-features
#RUN just test "tcp://localhost:2375" || (echo "Test are failing"; exit 1)

#ENV RUSTFLAGS="-C link-arg=-Wl,--compress-debug-sections=zlib -C force-frame-pointers=yes"
RUN cargo build --tests
#RUN cargo build --release --all-features


############################################################
# Builder for production image
FROM ${BUILDER_IMAGE} AS builder_release

WORKDIR /build
COPY . ./

ARG BIN_TARGET=--bins
ARG PROFILE=release

#ENV RUSTFLAGS="-C link-arg=-Wl,--compress-debug-sections=zlib -C force-frame-pointers=yes"
RUN cargo build --features=jemalloc --profile=${PROFILE} ${BIN_TARGET}


############################################################
# Final image
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS final-image

RUN useradd -ms /bin/bash app && \
        apt-get update && \
        apt-get -y upgrade && \
        apt install -y --no-install-recommends ca-certificates dumb-init && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists

WORKDIR /home/app

ARG PROFILE=release
COPY --from=builder_release  /build/target/${PROFILE}/tunward tunward

ENV RUST_LOG="INFO"
ENV SERVER_PROTOCOL="wss"
ENV SERVER_LISTEN="[::]"
ENV SERVER_PORT="8080"
EXPOSE 8080

USER app

ENTRYPOINT ["/usr/bin/dumb-init", "-v", "--"]
# The default server is complete and secure. It expects these files mounted read-only, and
# refuses to start without them:
#   /etc/tunward/tls/server.pem, /etc/tunward/tls/server.key, /etc/tunward/tls/client-ca.pem
#   /etc/tunward/restrictions.yaml
# Override the command to run a client or other options.
CMD ["/bin/sh", "-c", "exec /home/app/tunward server --tls-certificate /etc/tunward/tls/server.pem --tls-private-key /etc/tunward/tls/server.key --tls-client-ca-certs /etc/tunward/tls/client-ca.pem --restrict-config /etc/tunward/restrictions.yaml ${SERVER_PROTOCOL}://${SERVER_LISTEN}:${SERVER_PORT}"]
