# OAST Service

Ghost Listener provides a tiny out-of-band interaction collector for DNS, HTTP, SMTP, and webhook callbacks.

## Python app

- `services/oast/app.py` exposes a FastAPI app with a shared in-memory interaction store.
- `services/oast/http/server.py` records HTTP callback metadata.
- `services/oast/smtp/server.py` records SMTP callback metadata.
- `services/oast/webhook/server.py` delivers outbound webhook notifications.

## Notes

The repository also contains a Rust DNS listener under `services/oast/dns/src/main.rs`. The Python app here is a lightweight companion collector and can be run independently.
