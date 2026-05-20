# syntax=docker/dockerfile:1.7
# Multi-arch image for Heartwood signing software.
# Built and tested for linux/amd64, linux/arm64, linux/arm/v7.
#
# Local build:           docker build -t heartwood:dev .
# Multi-arch build:      docker buildx build --platform linux/arm64,linux/arm/v7,linux/amd64 -t heartwood:dev .
# Cross-arch test (e.g. verify on ARMv7 from x86 / Apple Silicon host):
#   docker run --rm --platform=linux/arm/v7 heartwood:dev heartwood --version

ARG RUST_VERSION=1.94
ARG NODE_VERSION=20
ARG DEBIAN_RELEASE=bookworm

# ---------- Stage 1: Rust builder ----------
# Builds inside TARGETPLATFORM (via buildx + QEMU when cross-arch) so the
# binary natively matches the runtime stage. Slower than cross-compilation
# but reliable and avoids per-target toolchain wrangling.
FROM --platform=$TARGETPLATFORM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS rust-builder

# libudev is needed by the device crate (HSM serial detection).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libudev-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Required by include_str! in heartwood-device for embedding the web UI.
COPY web ./web

RUN cargo build --release -p heartwood-device \
    && strip target/release/heartwood-device

# ---------- Stage 2: Bunker dependencies ----------
FROM --platform=$TARGETPLATFORM node:${NODE_VERSION}-${DEBIAN_RELEASE}-slim AS bunker-builder

WORKDIR /bunker
COPY bunker/package.json bunker/package-lock.json* ./
RUN npm ci --omit=dev --no-audit --no-fund

COPY bunker/index.mjs bunker/lib.mjs ./
COPY bunker/test ./test

# ---------- Stage 3: Runtime ----------
FROM --platform=$TARGETPLATFORM node:${NODE_VERSION}-${DEBIAN_RELEASE}-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        tor \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -s /usr/sbin/nologin heartwood

COPY --from=rust-builder /build/target/release/heartwood-device /usr/local/bin/heartwood
COPY --from=bunker-builder /bunker /opt/heartwood/bunker
COPY web /opt/heartwood/web
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/torrc /etc/tor/torrc.heartwood

RUN chmod +x /usr/local/bin/heartwood /usr/local/bin/entrypoint.sh \
    && mkdir -p /var/lib/heartwood /var/lib/tor/heartwood /run/heartwood \
    && chown -R heartwood:heartwood /var/lib/heartwood /var/lib/tor/heartwood /run/heartwood /opt/heartwood

ENV HEARTWOOD_DATA_DIR=/var/lib/heartwood \
    HEARTWOOD_BUNKER_DIR=/opt/heartwood/bunker \
    HEARTWOOD_WEB_DIR=/opt/heartwood/web \
    HEARTWOOD_BIND=0.0.0.0:3000 \
    NODE_ENV=production

EXPOSE 3000
VOLUME ["/var/lib/heartwood"]

USER heartwood
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
