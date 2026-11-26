"""Loopback-only adapter exposing the vendored HackBot runtime to GHOSTRECON.

The public GHOSTRECON API remains the authorization boundary. This sidecar uses
an independent per-install service token and never accepts model credentials in
request bodies.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import importlib.util
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve().parent / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

AGENTS = ("orchestrator", "researcher", "analyst", "document_analyst", "tutor")
SESSION_ID = re.compile(r"^[a-f0-9-]{10,40}$")
SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]{12,}"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret)\s*[=:]\s*)\S+"),
)

app = FastAPI(title="GHOSTRECON HackBot adapter", docs_url=None, redoc_url=None)
# The upstream MCP server keeps the loaded document in process-global state.
# Serialize by default; operators may opt into more only after providing an
# isolated external MCP transport per run.
run_slots = asyncio.Semaphore(max(1, min(int(os.getenv("GHOSTRECON_HACKBOT_CONCURRENCY", "1")), 4)))
session_locks: dict[str, asyncio.Lock] = {}


class RunRequest(BaseModel):
    session_id: str
    prompt: str = Field(min_length=1, max_length=64_000)
    agent: str = "orchestrator"
    document_path: str | None = None
    sarif_path: str | None = None
    document_desc: str = Field(default="", max_length=500)


def _redact(value: object) -> str:
    text = str(value)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda match: f"{match.group(1) if match.lastindex else ''}[REDACTED]", text)
    return text[:1_500]


def _provider_failure(value: object) -> tuple[int, str]:
    """Turn provider failures into actionable, stable API errors.

    Provider bridges may wrap a quota response in a 502. Classify from the
    preserved body so the React client can distinguish a plan limit from a
    transient gateway failure without exposing credentials.
    """
    text = _redact(value)
    lowered = text.lower()
    if "subscription sharing usage limit" in lowered:
        return (
            429,
            "Limite do perfil ChatGPT/Codex atingido. Aguarde a renovação do plano "
            "ou selecione, na aba Modelos, um perfil configurado com chave de API.",
        )
    if "stream ended before" in lowered:
        return (
            503,
            "O provedor encerrou o stream antes de concluir a resposta. Tente novamente; "
            "se persistir, teste o perfil na GhostIA ou selecione outro perfil.",
        )
    raw_status = getattr(value, "status_code", None)
    try:
        status = int(raw_status)
    except (TypeError, ValueError):
        status = 502
    if status not in {400, 401, 402, 403, 408, 409, 422, 429, 502, 503, 504}:
        status = 502
    return status, text


def _dependency_state() -> dict[str, bool]:
    return {
        name: importlib.util.find_spec(name) is not None
        for name in ("pydantic_ai", "mcp", "acp_sdk", "dotenv")
    }


def _require_service_token(x_ghostrecon_service_token: str = Header(default="")) -> None:
    expected = os.getenv("GHOSTRECON_HACKBOT_SERVICE_TOKEN", "")
    if not expected or not hmac.compare_digest(expected, x_ghostrecon_service_token):
        raise HTTPException(status_code=401, detail="invalid internal service token")


def _session_id(value: str) -> str:
    normalized = value.strip().lower()
    if not SESSION_ID.fullmatch(normalized):
        raise HTTPException(status_code=400, detail="invalid session id")
    return normalized


def _allowed_roots() -> list[Path]:
    configured = [part for part in os.getenv("GHOSTRECON_HACKBOT_ALLOWED_ROOTS", "").split(os.pathsep) if part]
    defaults = [ROOT / "reports", ROOT / "logs", ROOT / ".runtime", Path(__file__).resolve().parent / "samples"]
    roots = configured or [str(item) for item in defaults]
    return [Path(item).expanduser().resolve() for item in roots]


def _safe_document(value: str | None) -> str | None:
    if not value:
        return None
    candidate = Path(value).expanduser().resolve(strict=True)
    if not candidate.is_file():
        raise HTTPException(status_code=400, detail="document must be a regular file")
    if not any(candidate == root or root in candidate.parents for root in _allowed_roots()):
        raise HTTPException(status_code=403, detail="document path is outside HackBot allowed roots")
    return str(candidate)


def _load_runtime():
    missing = [name for name, ready in _dependency_state().items() if not ready]
    if missing:
        raise HTTPException(status_code=503, detail=f"HackBot dependencies missing: {', '.join(missing)}")
    from hackbot.agents import AgentSystem  # pylint: disable=import-outside-toplevel
    from hackbot.agents.runtime import history_from_entries  # pylint: disable=import-outside-toplevel
    from hackbot.config import Config  # pylint: disable=import-outside-toplevel
    from hackbot.history import Session, SessionStore  # pylint: disable=import-outside-toplevel

    return AgentSystem, history_from_entries, Config, Session, SessionStore


def _artex_password() -> str:
    value = os.getenv("ARTEX_ADMIN_PASSWORD", "").strip()
    if value:
        return value
    path = ROOT / ".runtime" / "artex" / "admin-password"
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise HTTPException(status_code=503, detail="GhostIA/Artex credential is unavailable") from exc


async def _connect_artex(cfg: Any) -> None:
    """Obtain an Artex session for its local inference bridge.

    The provider API key and ChatGPT Plan refresh token never cross this boundary;
    only Artex's ordinary, short-lived application session is held in memory.
    """
    parsed = urlparse(str(cfg.artex_base_url))
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise HTTPException(status_code=503, detail="HackBot only accepts a loopback GhostIA/Artex bridge")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{cfg.artex_base_url}/api/auth/login",
                json={"username": "ARTEX", "password": _artex_password()},
            )
            response.raise_for_status()
            token = str(response.json().get("token") or "").strip()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"GhostIA/Artex bridge unavailable: {_redact(exc)}") from exc
    if not token:
        raise HTTPException(status_code=503, detail="GhostIA/Artex did not issue a session")
    cfg.artex_access_token = token


def _public_usage(usage: Any) -> dict[str, int]:
    return {
        "input_tokens": int(getattr(usage, "input_tokens", 0) or 0),
        "output_tokens": int(getattr(usage, "output_tokens", 0) or 0),
        "requests": int(getattr(usage, "requests", 0) or 0),
        "tool_calls": int(getattr(usage, "tool_calls", 0) or 0),
    }


@app.get("/health")
async def health() -> dict[str, Any]:
    dependencies = _dependency_state()
    return {
        "ok": True,
        "service": "ghostrecon-hackbot",
        "runtime_ready": all(dependencies.values()),
        "dependencies": dependencies,
    }


@app.get("/v1/status", dependencies=[Depends(_require_service_token)])
async def status() -> dict[str, Any]:
    dependencies = _dependency_state()
    response: dict[str, Any] = {
        "ok": True,
        "runtime_ready": all(dependencies.values()),
        "dependencies": dependencies,
        "agents": list(AGENTS),
    }
    if response["runtime_ready"]:
        try:
            _, _, Config, _, _ = _load_runtime()
            response["bindings"] = Config.load().public_bindings()
        except Exception as exc:  # status remains useful when configuration is broken
            response["configuration_error"] = _redact(exc)
    return response


@app.get("/v1/sessions/{session_id}", dependencies=[Depends(_require_service_token)])
async def get_session(session_id: str) -> dict[str, Any]:
    sid = _session_id(session_id)
    _, _, Config, _, SessionStore = _load_runtime()
    try:
        session = SessionStore(Config.load().data_dir).load(sid)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="session not found") from exc
    return {"ok": True, "session": vars(session)}


@app.delete("/v1/sessions/{session_id}", dependencies=[Depends(_require_service_token)])
async def delete_session(session_id: str) -> dict[str, Any]:
    sid = _session_id(session_id)
    _, _, Config, _, SessionStore = _load_runtime()
    SessionStore(Config.load().data_dir).delete(sid)
    session_locks.pop(sid, None)
    return {"ok": True}


@app.post("/v1/runs", dependencies=[Depends(_require_service_token)])
async def run(request: RunRequest) -> dict[str, Any]:
    sid = _session_id(request.session_id)
    if request.agent not in AGENTS:
        raise HTTPException(status_code=400, detail="unknown HackBot agent")
    document_path = _safe_document(request.document_path)
    sarif_path = _safe_document(request.sarif_path)
    AgentSystem, history_from_entries, Config, Session, SessionStore = _load_runtime()
    cfg = Config.load()
    binding = cfg.binding_for(request.agent)
    if binding.source == "artex" or (request.agent == "orchestrator" and cfg.uses_artex()):
        await _connect_artex(cfg)
    if not cfg.ready_for(request.agent):
        binding = cfg.binding_for(request.agent)
        raise HTTPException(
            status_code=503,
            detail=f"model for {request.agent} is not ready; configure environment variable {binding.api_key_env}",
        )

    store = SessionStore(cfg.data_dir)
    lock = session_locks.setdefault(sid, asyncio.Lock())
    async with run_slots, lock:
        try:
            try:
                session = store.load(sid)
            except FileNotFoundError:
                session = Session(id=sid)
            previous_entries = list(session.entries)
            history = history_from_entries(previous_entries, cfg.history_window)
            session.add("user", request.prompt, agent=request.agent)
            language = os.getenv("GHOSTRECON_HACKBOT_LANGUAGE", "pt-BR").strip()
            prompt = request.prompt
            if language:
                prompt = f"Responda no idioma {language}.\n\nSolicitação do operador:\n{request.prompt}"
            timeout_seconds = max(10, min(int(os.getenv("GHOSTRECON_HACKBOT_RUN_TIMEOUT", "600")), 900))
            # AgentSystem owns API-backed specialists and Codex CLI agents. A
            # single path preserves specialist delegation before the central
            # Codex consolidation instead of bypassing the multi-agent team.
            async with asyncio.timeout(timeout_seconds):
                async with AgentSystem(cfg) as system:
                    outcome = await system.run(
                        prompt,
                        sarif_path=sarif_path,
                        document_path=document_path,
                        document_desc=request.document_desc,
                        message_history=history,
                        agent=request.agent,
                    )
            session.add(
                "assistant",
                outcome.answer,
                agent=request.agent,
                sources=outcome.sources,
                triage=outcome.triage,
                doc_report=outcome.doc_report,
                steps=outcome.steps,
                usage=_public_usage(outcome.usage),
                seconds=round(outcome.seconds, 3),
            )
            store.save(session)
            return {
                "ok": True,
                "session": vars(session),
                "outcome": {
                    "answer": outcome.answer,
                    "sources": outcome.sources,
                    "triage": outcome.triage,
                    "doc_report": outcome.doc_report,
                    "steps": outcome.steps,
                    "usage": _public_usage(outcome.usage),
                    "seconds": round(outcome.seconds, 3),
                },
            }
        except HTTPException:
            raise
        except TimeoutError as exc:
            session.add("error", "HackBot run timed out", agent=request.agent)
            store.save(session)
            raise HTTPException(status_code=504, detail="HackBot run timed out") from exc
        except Exception as exc:
            status, public = _provider_failure(exc)
            session.add("error", public, agent=request.agent)
            store.save(session)
            raise HTTPException(status_code=status, detail=public) from exc


def main() -> None:
    parser = argparse.ArgumentParser(prog="hackbot-ghostrecon")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8791, type=int)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("HackBot adapter only supports loopback binds")
    if not os.getenv("GHOSTRECON_HACKBOT_SERVICE_TOKEN"):
        raise SystemExit("GHOSTRECON_HACKBOT_SERVICE_TOKEN is required")
    import uvicorn  # pylint: disable=import-outside-toplevel

    uvicorn.run(app, host=args.host, port=args.port, access_log=False)


if __name__ == "__main__":
    main()
