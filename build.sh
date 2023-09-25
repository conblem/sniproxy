#!/usr/bin/env bash

cross build --target aarch64-unknown-linux-musl --release
cp target/aarch64-unknown-linux-musl/release/sniproxy arm64
docker build . -t conblem/sniproxy:latest --platform=linux/arm64