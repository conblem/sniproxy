FROM --platform=linux/amd64 rust:alpine as builder
#FROM rust:alpine as builder

RUN rustup target add x86_64-unknown-linux-musl

RUN apk update
RUN apk add --no-cache mold musl-dev musl clang

WORKDIR /app
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY .cargo/config.toml .cargo/config.toml

COPY fake.rs src/main.rs
RUN cargo fetch --target=x86_64-unknown-linux-musl
RUN RUSTFLAGS="--cfg tokio_unstable" cargo build --release --target=x86_64-unknown-linux-musl

COPY src src
RUN touch src/main.rs
RUN RUSTFLAGS="--cfg tokio_unstable" cargo build --release --target=x86_64-unknown-linux-musl

#ENTRYPOINT ["tail", "-f", "/dev/null"]

FROM --platform=linux/amd64 scratch

WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/sniproxy /app/sniproxy

ENTRYPOINT ["/app/sniproxy"]