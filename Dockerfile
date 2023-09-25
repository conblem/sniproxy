#FROM --platform=linux/amd64 ghcr.io/cross-rs/x86_64-unknown-linux-musl:main as builder
#FROM rust:alpine as builder

#RUN rustup target add x86_64-unknown-linux-musl

#RUN apk update
#RUN apk add --no-cache mold musl-dev musl clang gcc libc-dev
#
#WORKDIR /app
#COPY Cargo.toml Cargo.toml
#COPY Cargo.lock Cargo.lock
#COPY .cargo/config.toml .cargo/config.toml
#
#COPY fake.rs src/main.rs
#RUN cargo fetch --target=x86_64-unknown-linux-musl
#RUN cargo build --release --target=x86_64-unknown-linux-musl
#
#COPY src src
#RUN touch src/main.rs
#RUN cargo build --release --target=x86_64-unknown-linux-musl

FROM scratch

WORKDIR /app
ARG TARGETARCH
COPY $TARGETARCH /app/sniproxy

ENTRYPOINT ["/app/sniproxy"]