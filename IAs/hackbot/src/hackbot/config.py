"""Runtime configuration, loaded from environment / .env and saveable back to .env."""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

DEFAULT_MODEL = "gpt-5.6-luna"
AGENT_NAMES = ("orchestrator", "researcher", "analyst", "document_analyst", "tutor")
MODEL_CHOICES = [
    "gpt-5.6-luna",
    "gpt-4.1-nano",
    "gpt-4.1-mini",
    "gpt-4o-mini",
    "gpt-5-nano",
    "gpt-5-mini",
]

_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _env(name: str) -> str | None:
    """HACKBOT_<name>, falling back to the legacy CSRA_<name> from older .env files."""
    return os.getenv(f"HACKBOT_{name}") or os.getenv(f"CSRA_{name}") or None


def _default_data_dir() -> Path:
    new, old = Path.home() / ".hackbot", Path.home() / ".csra"
    if not new.exists() and old.exists():  # migrate sessions/triage from the old name
        try:
            old.rename(new)
        except OSError:
            return old
    return new


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _text(value: Any, limit: int = 500) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    return result[:limit] or None


@dataclass(frozen=True)
class AgentModelBinding:
    """Public, secret-free model selection for one HackBot agent.

    API keys are referenced by environment-variable name. This lets the React
    panel persist role/model routing without writing credentials to JSON.
    """

    model: str | None = None
    base_url: str | None = None
    api_key_env: str = "OPENAI_API_KEY"
    # direct = ordinary OpenAI-compatible endpoint; artex = a credential-owning
    # GhostIA profile reached through Artex's authenticated local bridge.
    source: str = "direct"
    profile_id: int | None = None
    provider: str = "openai"
    mcp_servers: tuple[str, ...] = ()

    def public_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
            "source": self.source,
            "profile_id": self.profile_id,
            "provider": self.provider,
            "mcp_servers": list(self.mcp_servers),
        }


def _binding_from(value: Any) -> AgentModelBinding:
    row = value if isinstance(value, dict) else {}
    api_key_env = (_text(row.get("api_key_env"), 100) or "OPENAI_API_KEY").upper()
    if not _ENV_NAME.fullmatch(api_key_env):
        api_key_env = "OPENAI_API_KEY"
    source = (_text(row.get("source"), 20) or "direct").lower()
    if source not in ("direct", "artex", "codex-cli"):
        source = "direct"
    try:
        profile_id = int(row.get("profile_id")) if row.get("profile_id") is not None else None
    except (TypeError, ValueError):
        profile_id = None
    if profile_id is not None and profile_id <= 0:
        profile_id = None
    mcp_servers: list[str] = []
    for raw in row.get("mcp_servers", []) if isinstance(row.get("mcp_servers"), list) else []:
        mcp_id = _text(raw, 80)
        if mcp_id and re.fullmatch(r"(?:codex:)?[A-Za-z0-9][A-Za-z0-9._-]{0,79}", mcp_id):
            if mcp_id not in mcp_servers:
                mcp_servers.append(mcp_id)
        if len(mcp_servers) >= 16:
            break
    return AgentModelBinding(
        model=_text(row.get("model")),
        base_url=_text(row.get("base_url"), 2_000),
        api_key_env=api_key_env,
        source=source,
        profile_id=profile_id,
        provider=(_text(row.get("provider"), 40) or "openai").lower(),
        mcp_servers=tuple(mcp_servers) if source == "codex-cli" else (),
    )


def _load_bindings_file(path: Path | None) -> dict[str, AgentModelBinding]:
    if not path or not path.is_file():
        return {}
    try:
        if path.stat().st_size > 256 * 1024:
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    rows = payload.get("bindings", payload) if isinstance(payload, dict) else {}
    if not isinstance(rows, dict):
        return {}
    return {
        name: _binding_from(rows.get(name))
        for name in AGENT_NAMES
        if isinstance(rows.get(name), dict)
    }


@dataclass
class Config:
    api_key: str | None = None
    model: str = DEFAULT_MODEL
    base_url: str | None = None
    data_dir: Path = field(default_factory=_default_data_dir)
    max_tool_steps: int = 6
    history_window: int = 20  # how many past turns are sent to the model
    web_search: bool = True  # allow web_search / fetch_page tools
    stream: bool = True  # stream tokens into the UI
    show_activity: bool = True  # activity (chain-of-thought) panel visible by default
    max_researchers: int = 3  # parallel researcher agents per question
    acp_url: str | None = None  # remote ACP server, e.g. http://127.0.0.1:8000
    mcp_config: str | None = None  # optional mcpServers JSON config with extra MCP servers
    model_bindings_file: Path | None = None  # secret-free JSON managed by GHOSTRECON
    agent_bindings: dict[str, AgentModelBinding] = field(default_factory=dict)
    artex_base_url: str = "http://127.0.0.1:8787"
    artex_access_token: str | None = field(default=None, repr=False)
    env_path: Path = field(default_factory=lambda: Path.cwd() / ".env")

    @property
    def ready(self) -> bool:
        return self.ready_for("orchestrator")

    def binding_for(self, agent: str) -> AgentModelBinding:
        """Return the effective role binding, falling back to legacy globals."""
        if agent not in AGENT_NAMES:
            raise KeyError(f"unknown HackBot agent: {agent}")
        binding = self.agent_bindings.get(agent, AgentModelBinding())
        if binding.source == "artex" and binding.profile_id:
            return AgentModelBinding(
                model=binding.model or self.model,
                base_url=f"{self.artex_base_url.rstrip('/')}/api/hackbot/llm/profiles/{binding.profile_id}/v1",
                api_key_env="ARTEX_INTERNAL_SESSION",
                source="artex",
                profile_id=binding.profile_id,
                provider=binding.provider,
                mcp_servers=(),
            )
        if binding.source == "codex-cli":
            return AgentModelBinding(
                model=binding.model or self.model,
                api_key_env="CODEX_LOGIN",
                source="codex-cli",
                provider="codex-cli",
                mcp_servers=binding.mcp_servers,
            )
        return AgentModelBinding(
            model=binding.model or self.model,
            base_url=binding.base_url or self.base_url,
            api_key_env=binding.api_key_env or "OPENAI_API_KEY",
            source="direct",
            provider=binding.provider or "openai",
            mcp_servers=(),
        )

    def api_key_for(self, agent: str) -> str | None:
        binding = self.binding_for(agent)
        if binding.source == "artex":
            return self.artex_access_token
        if binding.source == "codex-cli":
            return None
        return os.getenv(binding.api_key_env) or self.api_key

    def ready_for(self, agent: str) -> bool:
        binding = self.binding_for(agent)
        if binding.source == "artex":
            return bool(binding.profile_id)
        if binding.source == "codex-cli":
            return shutil.which("codex") is not None
        if self.api_key_for(agent):
            return True
        url = (binding.base_url or "").lower()
        return url.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]"))

    def public_bindings(self) -> dict[str, dict[str, Any]]:
        """Expose routing state without ever returning an API key value."""
        result: dict[str, dict[str, Any]] = {}
        for name in AGENT_NAMES:
            binding = self.binding_for(name)
            result[name] = {
                **binding.public_dict(),
                "configured": self.ready_for(name),
                "api_key_present": bool(self.api_key_for(name)),
                "credential_source": (
                    "ghostia-profile" if binding.source == "artex"
                    else "codex-login" if binding.source == "codex-cli"
                    else "environment"
                ),
            }
        return result

    @classmethod
    def load(cls, model: str | None = None) -> "Config":
        env_path = Path.cwd() / ".env"
        load_dotenv(env_path)
        data_dir = Path(_env("DATA_DIR") or _default_data_dir()).expanduser()
        data_dir.mkdir(parents=True, exist_ok=True)
        bindings_raw = _env("MODEL_BINDINGS_FILE")
        bindings_file = Path(bindings_raw).expanduser() if bindings_raw else None
        bindings = _load_bindings_file(bindings_file)
        for name in AGENT_NAMES:
            prefix = name.upper()
            current = bindings.get(name, AgentModelBinding())
            api_key_env = (_env(f"{prefix}_API_KEY_ENV") or current.api_key_env).upper()
            if not _ENV_NAME.fullmatch(api_key_env):
                api_key_env = "OPENAI_API_KEY"
            bindings[name] = AgentModelBinding(
                model=_env(f"{prefix}_MODEL") or current.model,
                base_url=_env(f"{prefix}_BASE_URL") or current.base_url,
                api_key_env=api_key_env,
                source=current.source,
                profile_id=current.profile_id,
                provider=current.provider,
                mcp_servers=current.mcp_servers,
            )
        return cls(
            api_key=os.getenv("OPENAI_API_KEY") or None,
            model=model or _env("MODEL") or DEFAULT_MODEL,
            base_url=os.getenv("OPENAI_BASE_URL") or None,
            data_dir=data_dir,
            max_tool_steps=int(_env("MAX_TOOL_STEPS") or 6),
            web_search=_bool(_env("WEB_SEARCH"), True),
            stream=_bool(_env("STREAM"), True),
            show_activity=_bool(_env("SHOW_ACTIVITY"), True),
            max_researchers=max(1, min(int(_env("MAX_RESEARCHERS") or 3), 4)),
            acp_url=_env("ACP_URL") or None,
            mcp_config=_env("MCP_CONFIG") or None,
            model_bindings_file=bindings_file,
            agent_bindings=bindings,
            artex_base_url=(os.getenv("ARTEX_BASE_URL") or "http://127.0.0.1:8787").rstrip("/"),
            env_path=env_path,
        )

    def uses_artex(self) -> bool:
        return any(self.binding_for(name).source == "artex" for name in AGENT_NAMES)

    def to_env(self) -> dict[str, str]:
        return {
            "OPENAI_API_KEY": self.api_key or "",
            "HACKBOT_MODEL": self.model,
            "OPENAI_BASE_URL": self.base_url or "",
            "HACKBOT_DATA_DIR": str(self.data_dir),
            "HACKBOT_MAX_TOOL_STEPS": str(self.max_tool_steps),
            "HACKBOT_WEB_SEARCH": "true" if self.web_search else "false",
            "HACKBOT_STREAM": "true" if self.stream else "false",
            "HACKBOT_SHOW_ACTIVITY": "true" if self.show_activity else "false",
            "HACKBOT_MAX_RESEARCHERS": str(self.max_researchers),
            "HACKBOT_ACP_URL": self.acp_url or "",
            "HACKBOT_MCP_CONFIG": self.mcp_config or "",
            "HACKBOT_MODEL_BINDINGS_FILE": str(self.model_bindings_file or ""),
        }

    def save_env(self) -> Path:
        """Write settings to .env, preserving unrelated lines and comments."""
        values = self.to_env()
        lines: list[str] = []
        seen: set[str] = set()
        if self.env_path.exists():
            for raw in self.env_path.read_text(encoding="utf-8").splitlines():
                key = raw.split("=", 1)[0].strip().lstrip("#").strip() if "=" in raw else ""
                if key in values:
                    if key not in seen:
                        lines.append(f"{key}={values[key]}")
                        seen.add(key)
                    continue
                lines.append(raw)
        for key, val in values.items():
            if key not in seen:
                lines.append(f"{key}={val}")
        self.env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        for key, val in values.items():  # keep the running process in sync
            os.environ[key] = val
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.env_path
