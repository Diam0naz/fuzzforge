# The worker needs the Docker CLI, so build a static (musl) binary and copy it
# into the official CLI image. The socket mount that makes this work is a
# local-development convenience and a root-equivalent privilege; see README.
FROM rust:1.89-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY common ./common
COPY api ./api
COPY worker ./worker
RUN cargo build --release -p fuzzforge-worker

FROM docker:27-cli
RUN apk add --no-cache ca-certificates
COPY --from=build /src/target/release/fuzzforge-worker /usr/local/bin/fuzzforge-worker
ENV STORAGE_DIR=/data
ENTRYPOINT ["fuzzforge-worker"]
