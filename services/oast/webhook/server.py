from __future__ import annotations

from typing import Any, Dict

import requests

from ..storage.store import InteractionStore, default_store


def deliver_webhook(
    endpoint: str,
    payload: Dict[str, Any],
    store: InteractionStore = default_store,
) -> Dict[str, Any]:
    response = requests.post(endpoint, json=payload, timeout=15)
    interaction = store.record(
        "webhook",
        endpoint,
        endpoint,
        {
            "status_code": response.status_code,
            "response_text": response.text[:500],
            "payload": payload,
        },
    )
    return interaction.to_dict()
