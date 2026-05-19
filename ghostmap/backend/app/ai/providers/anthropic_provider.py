"""Anthropic Messages API."""
from __future__ import annotations

import anthropic

from app.ai.base import ChatMessage, LLMProvider, LLMResponse


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key) if api_key else None

    async def chat(
        self, model: str, messages: list[ChatMessage], *,
        max_tokens: int = 1024, temperature: float = 0.2, json_mode: bool = False,
    ) -> LLMResponse:
        if self._client is None:
            raise RuntimeError("ANTHROPIC_API_KEY ausente")
        system = "\n\n".join(m.content for m in messages if m.role == "system") or None
        user_msgs = [{"role": m.role, "content": m.content} for m in messages if m.role != "system"]
        if json_mode:
            user_msgs.append({"role": "user", "content": "Responda APENAS em JSON valido."})
        resp = await self._client.messages.create(
            model=model, max_tokens=max_tokens, temperature=temperature,
            system=system, messages=user_msgs,
        )
        text = "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")
        return LLMResponse(
            text=text,
            tokens_in=resp.usage.input_tokens, tokens_out=resp.usage.output_tokens,
            raw={"id": resp.id, "stop_reason": resp.stop_reason},
        )
