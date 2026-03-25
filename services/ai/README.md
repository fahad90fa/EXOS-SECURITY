# Nexus Sentinel AI Service

This service powers the `ExploitGPT` workflow used by Nexus Sentinel.

## Runtime

Set these environment variables before running the service:

- `NVIDIA_API_KEY`: required API token for NVIDIA Integrate
- `NVIDIA_MODEL`: optional model name, defaults to `mistralai/mistral-small-4-119b-2603`
- `NVIDIA_STREAM`: optional streaming toggle, defaults to `true`

## Install

```bash
python -m pip install -r services/ai/requirements.txt
```

## Run

```bash
export NVIDIA_API_KEY="..."
python services/ai/api/main.py
```

## Notes

- The service falls back to heuristic classification if the local transformer stack is unavailable.
- The exploit-generation prompt is intended for authorized security testing workflows only.
