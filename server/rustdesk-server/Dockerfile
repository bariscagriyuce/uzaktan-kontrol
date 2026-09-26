# Uzaktan Kontrol: hbbs/hbbr with device registration over TCP/WebSocket
# (see ../hbbs-websocket-registration.patch). The binaries are built by
# .github/workflows/server-hbbs-image.yml on the same Ubuntu release and copied
# from ./bin.
FROM ubuntu:24.04
COPY bin/hbbs bin/hbbr /usr/bin/
# Same data layout as rustdesk/rustdesk-server: keys and database in /root.
WORKDIR /root
ENV HOME=/root
