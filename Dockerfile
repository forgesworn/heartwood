# syntax=docker/dockerfile:1.7
# Multi-arch image for the Heartwood signing bridge — the headless daemon that
# connects Nostr relays to a USB-tethered hardware signer. It holds no key
# material and exposes no network service of its own (it makes outbound relay
# connections only); all signing happens on the device over serial.
#
# Local build:      docker build -t heartwood-bridge:dev .
# Multi-arch build: docker buildx build --platform linux/arm64,linux/arm/v7,linux/amd64 -t heartwood-bridge:dev .
# Run (pass the USB serial device through):
#   docker run --rm --device=/dev/ttyUSB0 \
#     -e HEARTWOOD_SERIAL_PORT=/dev/ttyUSB0 \
#     -v heartwood-data:/var/lib/heartwood heartwood-bridge:dev

ARG RUST_VERSION=1.94
ARG DEBIAN_RELEASE=bookworm

# ---------- Stage 1: Rust builder ----------
# Builds inside TARGETPLATFORM (via buildx + QEMU when cross-arch) so the binary
# natively matches the runtime stage. The bridge uses serialport with
# default-features off (no libudev) and rustls (no system OpenSSL), so the build
# needs no extra system libraries.
FROM --platform=$TARGETPLATFORM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS rust-builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p heartwood-bridge \
    && strip target/release/heartwood-bridge

# ---------- Stage 2: Runtime ----------
FROM --platform=$TARGETPLATFORM debian:${DEBIAN_RELEASE}-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -s /usr/sbin/nologin heartwood

COPY --from=rust-builder /build/target/release/heartwood-bridge /usr/local/bin/heartwood-bridge

RUN mkdir -p /var/lib/heartwood \
    && chown -R heartwood:heartwood /var/lib/heartwood

# HEARTWOOD_SERIAL_PORT and HEARTWOOD_RELAYS are supplied at run time (or via a
# config.json in the data dir). bridge.secret is provisioned onto the volume
# over USB with the `provision` CLI before first run.
ENV HEARTWOOD_DATA_DIR=/var/lib/heartwood
VOLUME ["/var/lib/heartwood"]

USER heartwood
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/heartwood-bridge"]
