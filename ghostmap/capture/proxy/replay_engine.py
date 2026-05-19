"""
GhostMap — Replay Engine

Reexecuta um http_request armazenado, com mutacoes opcionais (header swap,
body diff, query patch). Usado pelo backend ao endpoint /requests/{id}/replay.

Suporta:
  * troca de Authorization (replay como outra role -> base do role diff manual)
  * substituicao por path/value JSON pointer
  * raw edit (override completo)
  * HTTP/2 via httpx
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any

import httpx
import orjson


@dataclass
class ReplayMutation:
    """Mutacoes aplicaveis antes do disparo."""
    method_override: str | None = None
    url_override: str | None = None
    add_headers: dict[str, str] | None = None
    remove_headers: list[str] | None = None
    body_override: bytes | None = None
    json_pointer_patches: list[dict[str, Any]] | None = None  # RFC6902 (subset)


@dataclass
class ReplayResult:
    status: int
    headers: list[tuple[str, str]]
    body_b64: str
    body_text: str | None
    duration_ms: int


class ReplayEngine:
    """Executa replays com HTTP/2 e timeout configuravel."""

    def __init__(self, timeout: float = 15.0, verify: bool = False, http2: bool = True) -> None:
        self._client = httpx.AsyncClient(timeout=timeout, verify=verify, http2=http2, follow_redirects=False)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def replay(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes | None,
        mutation: ReplayMutation | None = None,
    ) -> ReplayResult:
        mutation = mutation or ReplayMutation()
        method = mutation.method_override or method
        url = mutation.url_override or url
        merged = self._merge_headers(headers, mutation.add_headers or {}, mutation.remove_headers or [])
        body_out = self._mutate_body(body, mutation)
        t0 = time.perf_counter()
        resp = await self._client.request(method, url, headers=dict(merged), content=body_out)
        duration_ms = int((time.perf_counter() - t0) * 1000)
        raw = resp.content or b""
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        return ReplayResult(
            status=resp.status_code,
            headers=list(resp.headers.items()),
            body_b64=base64.b64encode(raw).decode("ascii"),
            body_text=text,
            duration_ms=duration_ms,
        )

    @staticmethod
    def _merge_headers(
        original: list[tuple[str, str]],
        add: dict[str, str],
        remove: list[str],
    ) -> list[tuple[str, str]]:
        remove_lower = {h.lower() for h in remove} | {k.lower() for k in add.keys()}
        out: list[tuple[str, str]] = [(k, v) for k, v in original if k.lower() not in remove_lower]
        out.extend(add.items())
        return out

    @staticmethod
    def _mutate_body(body: bytes | None, mutation: ReplayMutation) -> bytes | None:
        if mutation.body_override is not None:
            return mutation.body_override
        if not mutation.json_pointer_patches or not body:
            return body
        try:
            doc = orjson.loads(body)
        except orjson.JSONDecodeError:
            return body  # nao mexe em body nao-JSON
        for patch in mutation.json_pointer_patches:
            op = patch.get("op")
            path = patch.get("path", "")
            value = patch.get("value")
            doc = _apply_jp(doc, op, path, value)
        return orjson.dumps(doc)


def _apply_jp(doc: Any, op: str | None, path: str, value: Any) -> Any:
    """Subset minusculo de JSON Patch: add/replace/remove. Suporta paths /a/b/0."""
    if not path:
        return value if op in ("add", "replace") else doc
    parts = [_unescape(p) for p in path.lstrip("/").split("/")]
    parent, key = _walk(doc, parts[:-1]), parts[-1]
    if isinstance(parent, list):
        idx = int(key)
        if op == "remove":
            parent.pop(idx)
        elif op == "add":
            parent.insert(idx, value)
        elif op == "replace":
            parent[idx] = value
    elif isinstance(parent, dict):
        if op == "remove":
            parent.pop(key, None)
        else:
            parent[key] = value
    return doc


def _walk(doc: Any, parts: list[str]) -> Any:
    cur = doc
    for p in parts:
        cur = cur[int(p)] if isinstance(cur, list) else cur[p]
    return cur


def _unescape(p: str) -> str:
    return p.replace("~1", "/").replace("~0", "~")
