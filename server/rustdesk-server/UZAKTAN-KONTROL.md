# rustdesk-server (Uzaktan Kontrol)

Upstream: https://github.com/rustdesk/rustdesk-server @ a7736be5e40f85bfc141120dce587e836e5d4b80
(hbb_common submodule: rustdesk/hbb_common @ 69cea8d)

Change: devices can register (RegisterPk) over TCP/WebSocket, not only UDP 21116.
The connection stays open with a 20 s heartbeat, and messages addressed to the
device (punch hole, relay requests) are delivered over it. This lets devices
behind a WebSocket-only proxy such as Cloudflare Tunnel be reached.

The whole change is in src/rendezvous_server.rs and is kept as
../hbbs-websocket-registration.patch for rebasing onto newer upstream versions.
Packaging directories not used here (debian, docker, kubernetes, ui, ...) were removed.
