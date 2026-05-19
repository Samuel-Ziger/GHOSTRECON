"""
Abstracoes da camada de AI.

LLMProvider:    interface comum (Anthropic, Gemini, OpenRouter, Ollama)
ProviderSpec:   "provider:model" referencia textual usada nas policies
ChatMessage:    par {role, content}
LLMResponse:    payload normalizado (text, tokens, cost, raw)
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

Role = Literal["system", "user", "assistant"]


@dataclass
class ChatMessage:
    role: Role
    content: str


@dataclass
class LLMResponse:
    text: str
    tokens_in: int | None = None
    tokens_out: int | None = None
    cost_usd: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderSpec:
    """Formato "provider:model". Ex: "anthropic:claude-sonnet-4-6"."""
    provider: str
    model: str

    @classmethod
    def parse(cls, spec: str) -> "ProviderSpec":
        if ":" not in spec:
            raise ValueError(f"spec invalida: {spec!r} — use 'provider:model'")
        p, m = spec.split(":", 1)
        return cls(provider=p, model=m)

    def __str__(self) -> str:
        return f"{self.provider}:{self.model}"


class LLMProvider(ABC):
    """Interface minima."""
    name: str

    @abstractmethod
    async def chat(
        self,
        model: str,
        messages: list[ChatMessage],
        *,
        max_tokens: int = 1024,
        temperature: float = 0.2,
        json_mode: bool = False,
    ) -> LLMResponse: ...
