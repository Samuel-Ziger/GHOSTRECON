"""
JWT introspection / redaction utilities.
NAO emite tokens — apenas inspeciona os que circulam pela aplicacao alvo.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
COOKIE_SENSITIVE = re.compile(r"(session|sess|sid|token|auth|jwt|bearer)", re.I)


def parse_jwt(token: str) -> dict[str, Any] | None:
    """Decodifica header+claims SEM verificar assinatura. Para fins de analise."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = _b64json(parts[0])
        claims = _b64json(parts[1])
    except Exception:
        return None
    return {"header": header, "claims": claims}


def _b64json(seg: str) -> dict[str, Any]:
    seg += "=" * (-len(seg) % 4)
    raw = base64.urlsafe_b64decode(seg.encode("ascii"))
    return json.loads(raw)


def redact_text(text: str) -> str:
    """Substitui JWTs e cookies sensiveis por placeholders."""
    if not text:
        return text
    text = JWT_RE.sub("<JWT_REDACTED>", text)
    return text


def redact_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for k, v in headers:
        if k.lower() in ("authorization", "cookie", "set-cookie", "x-api-key"):
            out.append((k, "<REDACTED>"))
        else:
            out.append((k, v))
    return out
