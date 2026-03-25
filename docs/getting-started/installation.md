# Installation

## Requirements

- Rust toolchain 1.78+
- Node.js 18+
- Python 3.11+
- PostgreSQL 14+ for persistence

## Local Setup

```bash
git clone https://github.com/nexussentinel/nexus-sentinel.git
cd nexus-sentinel
cargo build --workspace
cd desktop && npm install
```

## Launch

```bash
cargo run --bin nexus -- proxy --listen 127.0.0.1:8080
cargo run --bin nexus -- api --listen 127.0.0.1:3000
cd desktop && npm run dev
```

## AI Service

```bash
python -m pip install -r services/ai/requirements.txt
export NVIDIA_API_KEY="your-token"
python services/ai/api/main.py
```
