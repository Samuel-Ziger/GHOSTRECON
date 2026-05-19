"""OpenRouter — usa o endpoint OpenAI-compatible. Modelos sao strings tipo
'openai/gpt-5', 'anthropic/claude-3.5-sonnet', 'meta-llama/llama-3.1-405b'."""
from __future__ import annotations

import httpx

from app.ai.base import ChatMessage, LLMProvider, LLMResponse


class OpenRouterProvider(LLMProvider):
    name = "openrouter"
    base_url = "https://openrouter.ai/api/v1"

    def __init__(self, api_key: str) -> None:
        self._key = api_key
        self._http = httpx.AsyncClient(timeout=60.0)

    async def chat(
        self, model: str, messages: list[ChatMessage], *,
        max_tokens: int = 1024, temperature: float = 0.2, json_mode: bool = False,
    ) -> LLMResponse:
        if not self._key:
            raise RuntimeError("OPENROUTER_API_KEY ausente")
        payload: dict = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        headers = {
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://ghostmap.local",
            "X-Title": "GhostMap",
        }
        r = await self._http.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
        r.raise_for_status()
        data = r.json()
        choice = data["choices"][0]
        usage = data.get("usage") or {}
        return LLMResponse(
            text=choice["message"]["content"],
            tokens_in=usage.get("prompt_tokens"),
            tokens_out=usage.get("completion_tokens"),
            cost_usd=usage.get("total_cost"),
            raw={"id": data.get("id"), "model": data.get("model")},
        )

    async def aclose(self) -> None:
        await self._http.aclose()
