FROM rust:1.89-slim-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY common ./common
COPY api ./api
COPY worker ./worker
RUN cargo build --release -p fuzzforge-api

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/fuzzforge-api /usr/local/bin/fuzzforge-api
ENV BIND_ADDR=0.0.0.0:8080 \
    STORAGE_DIR=/data
EXPOSE 8080
ENTRYPOINT ["fuzzforge-api"]
