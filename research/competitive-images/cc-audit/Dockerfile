# syntax=docker/dockerfile:1.7

FROM rust:1.93.0-bookworm@sha256:d0a4aa3ca2e1088ac0c81690914a0d810f2eee188197034edf366ed010a2b382 AS dependencies
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY xtask/Cargo.toml ./xtask/Cargo.toml
COPY benches/scan_benchmark.rs ./benches/scan_benchmark.rs
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
