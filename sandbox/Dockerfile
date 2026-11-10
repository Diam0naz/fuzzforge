# syntax=docker/dockerfile:1.7
#
# Fuzzforge sandbox image.
#
# The digest of this image is part of the reproducibility contract. Build it,
# push it, record the digest, and set SANDBOX_IMAGE to registry/image@sha256:…
# The base image and Trident version below are tags on purpose only so the
# scaffold is buildable; pin both by digest/version before taking real money.

ARG RUST_IMAGE=rust:1.99-slim-bookworm
FROM ${RUST_IMAGE} AS build
ARG TRIDENT_VERSION=0.12.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev git \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install trident-cli --version "${TRIDENT_VERSION}" --locked

FROM rust:1.99-slim-bookworm
ARG TRIDENT_VERSION=0.12.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates jq libssl3 pkg-config libssl-dev util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -u 1000 -m -d /home/fuzz fuzz

COPY --from=build /usr/local/cargo/bin/trident /usr/local/cargo/bin/trident
COPY bin/fuzzforge-run bin/fuzzforge-reproduce /usr/local/bin/
RUN chmod 0755 /usr/local/bin/fuzzforge-run /usr/local/bin/fuzzforge-reproduce

# Cargo/rustup live in the image, but CARGO_HOME is on the writable tmpfs so
# unprivileged runs never need to write the read-only root filesystem.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/work/cargo \
    TRIDENT_VERSION=${TRIDENT_VERSION} \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Build the project, not the service, as the unprivileged user.
USER fuzz
WORKDIR /work
ENTRYPOINT []
CMD ["fuzzforge-run"]
