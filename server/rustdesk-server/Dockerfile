# Uzaktan Kontrol: hbbs/hbbr with device registration over TCP/WebSocket
# (see ../hbbs-websocket-registration.patch).
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin hbbs --bin hbbr

FROM debian:bookworm-slim
COPY --from=build /src/target/release/hbbs /src/target/release/hbbr /usr/bin/
# Same data layout as rustdesk/rustdesk-server: keys and database in /root.
WORKDIR /root
ENV HOME=/root
