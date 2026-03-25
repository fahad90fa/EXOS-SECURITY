# Configuration

Environment variables:

- `RUST_LOG`: logging level
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `NVIDIA_API_KEY`: AI service token
- `NVIDIA_MODEL`: optional NVIDIA model override

Suggested defaults:

```bash
export DATABASE_URL=postgres://localhost/nexus
export REDIS_URL=redis://localhost:6379
export RUST_LOG=info
```
