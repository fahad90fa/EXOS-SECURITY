from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, List, Optional
from uuid import uuid4


@dataclass(slots=True)
class Interaction:
    id: str
    kind: str
    source: str
    target: str
    payload: Dict[str, Any]
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class InteractionStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self._items: List[Interaction] = []

    def record(self, kind: str, source: str, target: str, payload: Dict[str, Any]) -> Interaction:
        interaction = Interaction(
            id=str(uuid4()),
            kind=kind,
            source=source,
            target=target,
            payload=payload,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        with self._lock:
            self._items.append(interaction)
        return interaction

    def list(self, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = [item for item in self._items if kind is None or item.kind == kind]
            return [item.to_dict() for item in items]

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            counts: Dict[str, int] = {}
            for item in self._items:
                counts[item.kind] = counts.get(item.kind, 0) + 1
            return {
                "total": len(self._items),
                "by_kind": counts,
            }


default_store = InteractionStore()
