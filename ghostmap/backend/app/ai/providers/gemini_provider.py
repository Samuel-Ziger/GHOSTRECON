"""Google Gemini."""
from __future__ import annotations

import asyncio

import google.generativeai as genai

from app.ai.base import ChatMessage, LLMProvider, LLMResponse


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self, api_key: str) -> None:
        self._enabled = bool(api_key)
        if self._enabled:
            genai.configure(api_key=api_key)

    async def chat(
        self, model: str, messages: list[ChatMessage], *,
        max_tokens: int = 1024, temperature: float = 0.2, json_mode: bool = False,
    ) -> LLMResponse:
        if not self._enabled:
            raise RuntimeError("GEMINI_API_KEY ausente")
        system = "\n\n".join(m.content for m in messages if m.role == "system") or None
        prompt = "\n\n".join(m.content for m in messages if m.role != "system")
        gen = genai.GenerativeModel(model_name=model, system_instruction=system)
        # SDK e sync; rodamos em thread.
        def _call() -> "genai.GenerateContentResponse":
            cfg = {"max_output_tokens": max_tokens, "temperature": temperature}
            if json_mode:
                cfg["response_mime_type"] = "application/json"
            return gen.generate_content(prompt, generation_config=cfg)
        resp = await asyncio.to_thread(_call)
        text = getattr(resp, "text", "") or ""
        usage = getattr(resp, "usage_metadata", None)
        return LLMResponse(
            text=text,
            tokens_in=getattr(usage, "prompt_token_count", None) if usage else None,
            tokens_out=getattr(usage, "candidates_token_count", None) if usage else None,
        )
