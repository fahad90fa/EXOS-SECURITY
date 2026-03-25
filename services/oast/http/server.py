from __future__ import annotations

from typing import Any, Dict, Mapping

from ..storage.store import InteractionStore, default_store


def record_http_interaction(
    method: str,
    url: str,
    headers: Mapping[str, str] | None = None,
    body: str | bytes | None = None,
    store: InteractionStore = default_store,
) -> Dict[str, Any]:
    payload = {
        "method": method.upper(),
        "headers": dict(headers or {}),
        "body": body.decode("utf-8", errors="replace") if isinstance(body, bytes) else (body or ""),
    }
    interaction = store.record("http", payload["method"], url, payload)
    return interaction.to_dict()
