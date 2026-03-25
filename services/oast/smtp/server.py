from __future__ import annotations

from typing import Any, Dict

from ..storage.store import InteractionStore, default_store


def record_smtp_interaction(
    client: str,
    helo: str,
    mail_from: str,
    rcpt_to: str,
    data: str = "",
    store: InteractionStore = default_store,
) -> Dict[str, Any]:
    payload = {
        "helo": helo,
        "mail_from": mail_from,
        "rcpt_to": rcpt_to,
        "data": data,
    }
    interaction = store.record("smtp", client, rcpt_to, payload)
    return interaction.to_dict()
