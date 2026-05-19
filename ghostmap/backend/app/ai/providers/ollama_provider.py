"""Ollama local — soberania de dados. Tambem usado para embeddings."""
from __future__ import annotations

import httpx

from app.ai.base import ChatMessage, LLMProvider, LLMResponse


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, base_url: str) -> None:
        self._base = base_url.rstrip("/")
        self._http = httpx.AsyncClient(timeout=120.0)

    async def chat(
        self, model: str, messages: list[ChatMessage], *,
        max_tokens: int = 1024, temperature: float = 0.2, json_mode: bool = False,
    ) -> LLMResponse:
        payload: dict = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if json_mode:
            payload["format"] = "json"
        r = await self._http.post(f"{self._base}/api/chat", json=payload)
        r.raise_for_status()
        data = r.json()
        msg = data.get("message", {})
        return LLMResponse(
            text=msg.get("content", ""),
            tokens_in=data.get("prompt_eval_count"),
            tokens_out=data.get("eval_count"),
            raw={"model": data.get("model"), "done_reason": data.get("done_reason")},
        )

    async def embed(self, model: str, text: str) -> list[float]:
        r = await self._http.post(f"{self._base}/api/embeddings", json={"model": model, "prompt": text})
        r.raise_for_status()
        return list(r.json().get("embedding", []))

    async def aclose(self) -> None:
        await self._http.aclose()
