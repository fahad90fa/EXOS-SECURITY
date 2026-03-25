# Nexus Sentinel Project

Nexus Sentinel is a modular security scanning platform for web applications, mobile apps, blockchain smart contracts, red team validation, reporting, and infrastructure operations.

## What lives in this repo

- `crates/core` - shared types, configuration, database access, and utilities.
- `crates/proxy` - MITM proxy and traffic interception.
- `crates/scanner` - web vulnerability detection engine.
- `crates/crawler` - web crawler and scope management.
- `crates/fuzzer` - adaptive fuzzing engine.
- `crates/mobile` - Android and iOS mobile analysis.
- `crates/blockchain` - Solidity, Web3, and smart contract analysis.
- `crates/redteam` - attack planning, reporting, and purple-team workflows.
- `crates/api` - HTTP API and websocket layer.
- `crates/cli` - command-line entrypoint.
- `desktop` - Tauri/Vue desktop UI.
- `dashboard` - dashboard shell and reusable widgets.
- `services/ai` - NVIDIA-backed AI service for analysis and classification.
- `services/oast` - out-of-band interaction collection services.
- `docs` - project documentation source tree.
- `payloads` - reusable payload corpora by vulnerability class.
- `migrations` - database schema migrations.
- `helm` and `terraform` - deployment and infrastructure definitions.

## Current feature areas

### Core web security
- HTTP proxying and interception
- Active scanning for XSS, SQLi, SSRF, XXE, SSTI, path traversal, CORS issues, open redirects, and headers
- Crawling, payload generation, and report output

### Mobile security
- APK and IPA parsing
- Manifest and plist security checks
- Resource extraction and secret scanning
- Static mobile risk scoring
- Desktop upload flow and API endpoint integration

### Blockchain and Web3
- Solidity analysis
- Smart contract heuristic detection
- Web3 frontend scanning
- CLI analysis commands and report generation

### Red team and purple team
- Attack planning and narrative generation
- Safe reporting primitives
- Detection and collaboration oriented workflows

### Dashboard and UI
- Vue/Tauri desktop experience
- Reusable dashboard widgets
- Marketplace widgets
- Traffic, scan, and report panels

### AI service
- NVIDIA Integrate chat-completions backend
- Optional local model fallback logic
- Classification and analysis helpers

### OAST
- DNS callback listener in Rust
- Python helper service for HTTP, SMTP, and webhook interaction capture

## Useful commands

### Rust workspace
```bash
cargo check
cargo test
cargo run --bin nexus -- --help
```

### CLI examples
```bash
cargo run --bin nexus -- scan https://example.com
cargo run --bin nexus -- crawl https://example.com
cargo run --bin nexus -- mobile analyze app.apk
cargo run --bin nexus -- blockchain analyze contract.sol
cargo run --bin nexus -- redteam plan https://target.example
```

### AI service
```bash
cd services/ai
pip install -r requirements.txt
export NVIDIA_API_KEY=...
python api/main.py
```

### OAST service
```bash
cd services/oast
pip install -r requirements.txt
uvicorn app:app --reload
```

### Desktop UI
```bash
cd desktop
npm install
npm run tauri dev
```

## Environment variables

- `NVIDIA_API_KEY` - NVIDIA Integrate token for the AI service.
- `NVIDIA_MODEL` - model name for NVIDIA chat completions.
- `NVIDIA_STREAM` - enable or disable streaming responses.
- `VITE_NEXUS_API_URL` - API base URL for the desktop upload flow.
- `DATABASE_URL` - PostgreSQL connection string.
- `REDIS_URL` - Redis connection string.

## Data folders

- `payloads/` contains curated payload files grouped by vulnerability type.
- `migrations/` contains SQL schema changes.
- `services/ai/data` and `services/ai/models` are reserved for local data and model artifacts.

## Deployment notes

- `docker-compose.yml` provides a local orchestration baseline.
- `Dockerfile.api` builds the API service image.
- `helm/` contains Kubernetes deployment templates.
- `terraform/` contains infrastructure definitions.

## Development notes

- The codebase is intentionally modular so each security domain can be extended independently.
- New functionality should include tests where practical and should prefer reusable components over one-off logic.
- Keep secrets out of source control and configure them through environment variables.

## Documentation

This file is the primary project overview. The repository `README.md` remains the quick-start entry point.
