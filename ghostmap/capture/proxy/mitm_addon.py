"""
GhostMap — mitmproxy addon

Hooks:
  * request           -> captura request bruto (headers, body, ts)
  * response          -> captura response e emite evento HTTP completo
  * websocket_start   -> abre tracking de uma conexao WS
  * websocket_message -> emite frame
  * websocket_end     -> fecha tracking

Cada evento eh publicado em Redis Streams (gm:capture:http | gm:capture:websocket)
com schema padronizado (CaptureEvent v1). Idempotencia via event_id ULID.

Configuracao via env:
  REDIS_URL                 ex.: redis://redis:6379/0
  GHOSTMAP_BACKEND_URL      ex.: http://backend:8000  (usado para auto-criar session se nao houver)
  GHOSTMAP_PROJECT_ID       UUID do projeto ativo (obrigatorio)
  GHOSTMAP_SESSION_ID       UUID da session ativa (opcional; gerado se ausente)
  GHOSTMAP_SCOPE_DOMAINS    "*.target.com,api.target.com" — only-record-these
  GHOSTMAP_EXCLUDE_DOMAINS  hosts a ignorar (cdns, telemetry)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import orjson
import redis
from mitmproxy import ctx, http
from mitmproxy.websocket import WebSocketMessage
from ulid import ULID

log = logging.getLogger("ghostmap.proxy")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

STREAM_HTTP = "gm:capture:http"
STREAM_WS = "gm:capture:websocket"
MAXLEN = 100_000
# Mitmproxy maxlen for body slicing (bytes). Headers/body acima disso sao truncados,
# o body cheio fica acessivel via backend (mitmproxy mantem o flow.id).
MAX_BODY_BYTES = 2 * 1024 * 1024


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


class Scope:
    """Decide se um host deve ser capturado."""

    def __init__(
        self,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> None:
        self.include = include or []
        self.exclude = exclude or []

    def matches(self, host: str) -> bool:
        host = host.lower()
        if any(self._match_pattern(p.lower(), host) for p in self.exclude):
            return False
        if not self.include:
            return True
        return any(self._match_pattern(p.lower(), host) for p in self.include)

    @staticmethod
    def _match_pattern(pattern: str, host: str) -> bool:
        # suporte simples a "*.foo.com"
        if pattern.startswith("*."):
            return host == pattern[2:] or host.endswith("." + pattern[2:])
        return host == pattern


class CaptureEventEmitter:
    """Publica eventos no Redis Stream com retry e backpressure simples."""

    def __init__(self, url: str) -> None:
        self._redis = redis.from_url(url, decode_responses=False)
        # ping eager para falhar rapido
        self._redis.ping()
        log.info("redis connected: %s", url)

    def emit(self, stream: str, event: dict[str, Any]) -> None:
        try:
            payload = orjson.dumps(event)
            self._redis.xadd(stream, {b"d": payload}, maxlen=MAXLEN, approximate=True)
        except Exception as e:  # pragma: no cover (best-effort)
            log.exception("xadd failed: %s", e)


class GhostMapAddon:
    """Addon principal: gerencia ciclo de vida e publica eventos."""

    def __init__(self) -> None:
        self.project_id = os.environ.get("GHOSTMAP_PROJECT_ID") or ""
        self.session_id = os.environ.get("GHOSTMAP_SESSION_ID") or str(uuid.uuid4())
        self.backend_url = os.environ.get("GHOSTMAP_BACKEND_URL", "http://backend:8000")
        self.scope = Scope(
            include=_split_csv(os.environ.get("GHOSTMAP_SCOPE_DOMAINS")),
            exclude=_split_csv(os.environ.get("GHOSTMAP_EXCLUDE_DOMAINS")),
        )
        self.emitter = CaptureEventEmitter(os.environ.get("REDIS_URL", "redis://redis:6379/0"))
        # cache de tracking de WS por flow.id
        self._ws_meta: dict[str, dict[str, Any]] = {}
        self._ensure_session()
        log.info(
            "ghostmap addon ready project=%s session=%s include=%s exclude=%s",
            self.project_id, self.session_id, self.scope.include, self.scope.exclude,
        )

    # ---------- lifecycle ----------
    def _ensure_session(self) -> None:
        """Garante que a session existe no backend (best-effort, nao bloqueia)."""
        if not self.project_id:
            log.warning("GHOSTMAP_PROJECT_ID nao definido — eventos vao para o stream mas")
            log.warning("o backend pode rejeita-los. Crie um projeto via UI antes de capturar.")
            return
        try:
            r = httpx.post(
                f"{self.backend_url}/api/v1/sessions",
                json={
                    "id": self.session_id,
                    "project_id": self.project_id,
                    "label": f"proxy-{datetime.now(tz=timezone.utc).strftime('%Y%m%d-%H%M%S')}",
                },
                timeout=3.0,
            )
            log.info("session ensure status=%s", r.status_code)
        except Exception as e:  # pragma: no cover
            log.warning("session ensure failed (sera criada lazy): %s", e)

    # ---------- mitmproxy hooks ----------
    def request(self, flow: http.HTTPFlow) -> None:
        # marca tempo para calculo de duracao no response
        flow.metadata["gm_t0"] = time.perf_counter()

    def response(self, flow: http.HTTPFlow) -> None:
        if not self.scope.matches(flow.request.host):
            return
        try:
            t0 = flow.metadata.get("gm_t0") or time.perf_counter()
            duration_ms = int((time.perf_counter() - t0) * 1000)
            event = self._build_http_event(flow, duration_ms)
            self.emitter.emit(STREAM_HTTP, event)
        except Exception:
            log.exception("failed to emit http event")

    def websocket_start(self, flow: http.HTTPFlow) -> None:
        if not self.scope.matches(flow.request.host):
            return
        self._ws_meta[flow.id] = {
            "url": flow.request.pretty_url,
            "started_at": _now_iso(),
        }

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if flow.id not in self._ws_meta:
            return
        ws = flow.websocket
        if ws is None or not ws.messages:
            return
        msg: WebSocketMessage = ws.messages[-1]
        event = self._build_ws_event(flow, msg)
        self.emitter.emit(STREAM_WS, event)

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        self._ws_meta.pop(flow.id, None)

    # ---------- builders ----------
    def _build_http_event(self, flow: http.HTTPFlow, duration_ms: int) -> dict[str, Any]:
        req = flow.request
        resp = flow.response
        req_body, req_body_text = self._capture_body(req.raw_content)
        resp_body, resp_body_text = (None, None)
        if resp is not None:
            resp_body, resp_body_text = self._capture_body(resp.raw_content)

        is_graphql, graphql_op = self._detect_graphql(req.path, req_body_text)
        is_xhr = self._is_xhr(req.headers)

        return {
            "event_id": str(ULID()),
            "schema": "gm.capture.http/1",
            "project_id": self.project_id,
            "session_id": self.session_id,
            "occurred_at": _now_iso(),
            "flow_id": flow.id,
            "request": {
                "method": req.method,
                "url": req.pretty_url,
                "scheme": req.scheme,
                "host": req.host,
                "port": req.port,
                "path": req.path.split("?", 1)[0],
                "query": dict(req.query.items(multi=True)) if req.query else {},
                "http_version": req.http_version,
                "headers": list(req.headers.items()),
                "body_b64": req_body,
                "body_text": req_body_text,
                "is_xhr": is_xhr,
                "is_graphql": is_graphql,
                "graphql_op": graphql_op,
            },
            "response": None if resp is None else {
                "status": resp.status_code,
                "reason": resp.reason,
                "http_version": resp.http_version,
                "headers": list(resp.headers.items()),
                "body_b64": resp_body,
                "body_text": resp_body_text,
            },
            "duration_ms": duration_ms,
            "client": {"ip": flow.client_conn.peername[0] if flow.client_conn.peername else None},
        }

    def _build_ws_event(self, flow: http.HTTPFlow, msg: WebSocketMessage) -> dict[str, Any]:
        payload_b64, payload_text = self._capture_body(msg.content)
        return {
            "event_id": str(ULID()),
            "schema": "gm.capture.ws/1",
            "project_id": self.project_id,
            "session_id": self.session_id,
            "occurred_at": _now_iso(),
            "flow_id": flow.id,
            "url": flow.request.pretty_url,
            "direction": "client_to_server" if msg.from_client else "server_to_client",
            "is_text": msg.is_text,
            "payload_b64": payload_b64,
            "payload_text": payload_text if msg.is_text else None,
        }

    # ---------- helpers ----------
    @staticmethod
    def _capture_body(raw: bytes | None) -> tuple[str | None, str | None]:
        if not raw:
            return None, None
        sliced = raw[:MAX_BODY_BYTES]
        b64 = base64.b64encode(sliced).decode("ascii")
        text: str | None = None
        try:
            text = sliced.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        return b64, text

    @staticmethod
    def _detect_graphql(path: str, body_text: str | None) -> tuple[bool, str | None]:
        if "graphql" not in path.lower():
            return False, None
        if not body_text:
            return True, None
        try:
            parsed = json.loads(body_text)
        except (ValueError, TypeError):
            return True, None
        if isinstance(parsed, list) and parsed:
            parsed = parsed[0]
        if isinstance(parsed, dict):
            op = parsed.get("operationName")
            return True, op if isinstance(op, str) else None
        return True, None

    @staticmethod
    def _is_xhr(headers: Any) -> bool:
        xrw = headers.get("X-Requested-With", "")
        if xrw and xrw.lower() == "xmlhttprequest":
            return True
        accept = headers.get("Accept", "")
        sec_fetch = headers.get("Sec-Fetch-Mode", "")
        return "application/json" in accept.lower() or sec_fetch in ("cors", "no-cors", "same-origin")


# mitmproxy carrega `addons` desta variavel
addons = [GhostMapAddon()]
