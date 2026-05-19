"""
AIOrchestrator — routing entre providers segundo policy do agente, com
retries, fallback automatico, redaction de PII/tokens e audit trail.

Policies sao YAML em backend/app/ai/policies/<agent>.yaml. Exemplo:

    agent: hypothesis_generator
    prefer:   ["anthropic:claude-sonnet-4-6", "openrouter:openai/gpt-5"]
    fallback: ["gemini:gemini-2.5-pro", "ollama:qwen3:32b"]
    max_cost_usd: 0.05
    require_json: true
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.ai.base import ChatMessage, LLMProvider, LLMResponse, ProviderSpec
from app.ai.providers import (
    AnthropicProvider, GeminiProvider, OllamaProvider, OpenRouterProvider,
)
from app.config import get_settings
from app.core.security import redact_text

log = logging.getLogger("ai.orchestrator")


@dataclass
class AgentPolicy:
    agent: str
    prefer: list[ProviderSpec]
    fallback: list[ProviderSpec] = field(default_factory=list)
    max_cost_usd: float | None = None
    require_json: bool = False
    redact: bool = True
    temperature: float = 0.2
    max_tokens: int = 1024


@dataclass
class InvocationResult:
    response: LLMResponse
    used: ProviderSpec
    duration_ms: int
    prompt_hash: str
    redacted: bool


class AIOrchestrator:
    """Encapsula resolucao de provider + execucao + auditoria."""

    POLICY_DIR = Path(__file__).parent / "policies"

    def __init__(self) -> None:
        s = get_settings()
        self._providers: dict[str, LLMProvider] = {
            "anthropic":  AnthropicProvider(s.anthropic_api_key),
            "gemini":     GeminiProvider(s.gemini_api_key),
            "openrouter": OpenRouterProvider(s.openrouter_api_key),
            "ollama":     OllamaProvider(s.ollama_base_url),
        }
        self._policies: dict[str, AgentPolicy] = {}
        self._load_policies()

    # ---------- policies ----------
    def _load_policies(self) -> None:
        if not self.POLICY_DIR.exists():
            return
        for path in self.POLICY_DIR.glob("*.yaml"):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                name = data["agent"]
                self._policies[name] = AgentPolicy(
                    agent=name,
                    prefer=[ProviderSpec.parse(s) for s in data.get("prefer", [])],
                    fallback=[ProviderSpec.parse(s) for s in data.get("fallback", [])],
                    max_cost_usd=data.get("max_cost_usd"),
                    require_json=bool(data.get("require_json", False)),
                    redact=bool(data.get("redact", True)),
                    temperature=float(data.get("temperature", 0.2)),
                    max_tokens=int(data.get("max_tokens", 1024)),
                )
            except Exception:
                log.exception("policy %s invalida", path.name)

    def get_policy(self, agent: str) -> AgentPolicy:
        if agent in self._policies:
            return self._policies[agent]
        # default conservador: tenta ollama (local) se nada estiver configurado
        return AgentPolicy(
            agent=agent,
            prefer=[ProviderSpec("ollama", "llama3.1:8b")],
            fallback=[],
        )

    # ---------- main API ----------
    async def run(
        self,
        agent: str,
        messages: list[ChatMessage],
        *,
        policy_override: AgentPolicy | None = None,
    ) -> InvocationResult:
        policy = policy_override or self.get_policy(agent)
        if policy.redact:
            messages = [ChatMessage(role=m.role, content=redact_text(m.content)) for m in messages]

        prompt_hash = self._hash([m.content for m in messages])
        order: list[ProviderSpec] = [*policy.prefer, *policy.fallback]
        last_err: Exception | None = None
        for spec in order:
            provider = self._providers.get(spec.provider)
            if provider is None:
                continue
            t0 = time.perf_counter()
            try:
                resp = await provider.chat(
                    model=spec.model, messages=messages,
                    max_tokens=policy.max_tokens,
                    temperature=policy.temperature,
                    json_mode=policy.require_json,
                )
                duration_ms = int((time.perf_counter() - t0) * 1000)
                if policy.max_cost_usd and resp.cost_usd and resp.cost_usd > policy.max_cost_usd:
                    raise RuntimeError(f"cost {resp.cost_usd} > limit {policy.max_cost_usd}")
                return InvocationResult(
                    response=resp, used=spec,
                    duration_ms=duration_ms, prompt_hash=prompt_hash,
                    redacted=policy.redact,
                )
            except Exception as e:
                last_err = e
                log.warning("provider %s falhou: %s — caindo p/ proximo", spec, e)
                await asyncio.sleep(0.2)
        raise RuntimeError(f"todos os providers falharam para agent={agent}: {last_err}")

    # ---------- helpers ----------
    @staticmethod
    def _hash(parts: list[str]) -> str:
        h = hashlib.sha256()
        for p in parts:
            h.update(p.encode("utf-8", errors="ignore"))
            h.update(b"\0")
        return h.hexdigest()


_singleton: AIOrchestrator | None = None


def get_orchestrator() -> AIOrchestrator:
    global _singleton
    if _singleton is None:
        _singleton = AIOrchestrator()
    return _singleton
