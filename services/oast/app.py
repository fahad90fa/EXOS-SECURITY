from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .http import record_http_interaction
from .smtp import record_smtp_interaction
from .storage import default_store


class HttpInteractionIn(BaseModel):
    method: str = Field(default="GET")
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = ""


class SmtpInteractionIn(BaseModel):
    client: str = Field(default="unknown")
    helo: str
    mail_from: str
    rcpt_to: str
    data: Optional[str] = ""


def create_app() -> FastAPI:
    app = FastAPI(title="Ghost Listener", version="0.1.0")

    @app.get("/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @app.get("/interactions")
    def list_interactions(kind: Optional[str] = None) -> Dict[str, Any]:
        return {
            "summary": default_store.summary(),
            "items": default_store.list(kind=kind),
        }

    @app.post("/interactions/http")
    def add_http_interaction(payload: HttpInteractionIn) -> Dict[str, Any]:
        if not payload.url:
            raise HTTPException(status_code=400, detail="url is required")
        return record_http_interaction(
            method=payload.method,
            url=payload.url,
            headers=payload.headers,
            body=payload.body or "",
        )

    @app.post("/interactions/smtp")
    def add_smtp_interaction(payload: SmtpInteractionIn) -> Dict[str, Any]:
        return record_smtp_interaction(
            client=payload.client,
            helo=payload.helo,
            mail_from=payload.mail_from,
            rcpt_to=payload.rcpt_to,
            data=payload.data or "",
        )

    return app


app = create_app()

