# syntax=docker/dockerfile:1.7

FROM rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS dependencies
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY xtask/Cargo.toml ./xtask/Cargo.toml
RUN mkdir -p src xtask/src \
    && printf 'fn main() {}\n' > src/main.rs \
    && printf 'fn main() {}\n' > xtask/src/main.rs \
    && cargo fetch --locked \
    && rm -rf src xtask/src

FROM dependencies AS builder
COPY . .
RUN --network=none cargo build --locked --release --bin cc-audit

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
COPY --from=builder /build/target/release/cc-audit /usr/local/bin/cc-audit
ENTRYPOINT ["/usr/local/bin/cc-audit"]
