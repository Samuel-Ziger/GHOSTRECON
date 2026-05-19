"""
HAR 1.2 exporter — converte requests armazenados em formato HAR padrao.
Aceito por DevTools, Burp, ZAP, Charles e similares.
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any, Iterable


def to_har(requests: Iterable[dict[str, Any]], creator: str = "GhostMap") -> dict[str, Any]:
    """`requests` deve ser uma sequencia de dicts no schema interno (http_requests)."""
    entries = [_entry(r) for r in requests]
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": creator, "version": "0.1.0"},
            "entries": entries,
        }
    }


def _entry(r: dict[str, Any]) -> dict[str, Any]:
    started = _iso(r.get("occurred_at"))
    req_headers = _headers(r.get("req_headers"))
    resp_headers = _headers(r.get("resp_headers"))
    return {
        "startedDateTime": started,
        "time": r.get("duration_ms", 0),
        "request": {
            "method": r.get("method", "GET"),
            "url": r.get("url", ""),
            "httpVersion": "HTTP/1.1",
            "headers": req_headers,
            "queryString": _kv(r.get("query") or {}),
            "headersSize": -1,
            "bodySize": len(r.get("req_body") or b""),
            "postData": _post_data(r.get("req_body"), r.get("req_body_text"), req_headers),
        },
        "response": {
            "status": r.get("status", 0),
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": resp_headers,
            "content": _content(r.get("resp_body"), r.get("resp_body_text"), resp_headers),
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(r.get("resp_body") or b""),
        },
        "cache": {},
        "timings": {"send": 0, "wait": r.get("duration_ms", 0), "receive": 0},
    }


def _iso(v: Any) -> str:
    if isinstance(v, datetime):
        return v.isoformat()
    return str(v) if v is not None else datetime.utcnow().isoformat()


def _headers(h: Any) -> list[dict[str, str]]:
    if not h:
        return []
    if isinstance(h, dict):
        return [{"name": k, "value": str(v)} for k, v in h.items()]
    if isinstance(h, list):
        return [{"name": str(k), "value": str(v)} for k, v in h]
    return []


def _kv(d: dict[str, Any]) -> list[dict[str, str]]:
    return [{"name": k, "value": str(v)} for k, v in d.items()]


def _post_data(body: bytes | None, text: str | None, headers: list[dict[str, str]]) -> dict[str, Any]:
    mime = next((h["value"] for h in headers if h["name"].lower() == "content-type"), "application/octet-stream")
    if text is not None:
        return {"mimeType": mime, "text": text}
    if body is None:
        return {"mimeType": mime, "text": ""}
    return {"mimeType": mime, "text": base64.b64encode(body).decode("ascii"), "encoding": "base64"}


def _content(body: bytes | None, text: str | None, headers: list[dict[str, str]]) -> dict[str, Any]:
    mime = next((h["value"] for h in headers if h["name"].lower() == "content-type"), "application/octet-stream")
    size = len(body or b"")
    if text is not None:
        return {"size": size, "mimeType": mime, "text": text}
    if body is None:
        return {"size": 0, "mimeType": mime, "text": ""}
    return {"size": size, "mimeType": mime, "text": base64.b64encode(body).decode("ascii"), "encoding": "base64"}
