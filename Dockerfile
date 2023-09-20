FROM --platform=linux/amd64 rust:alpine as builder
#FROM rust:alpine as builder

RUN rustup target add x86_64-unknown-linux-musl

RUN apk update
RUN apk add --no-cache mold musl-dev

WORKDIR /app
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock

COPY fake.rs src/main.rs
RUN cargo build --release --target=x86_64-unknown-linux-musl

#RUN rm -rf ./src
COPY src src
RUN touch src/main.rs
RUN cargo build --release --target=x86_64-unknown-linux-musl


FROM --platform=linux/amd64 scratch

WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/sniproxy /app/sniproxy

ENTRYPOINT ["/app/sniproxy"]