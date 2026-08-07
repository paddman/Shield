from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .config import Settings

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class LlmResult:
    data: dict[str, Any]
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: int


class OpenAICompatibleLlm:
    """Small OpenAI-compatible client for local Qwen via vLLM/SGLang/Ollama gateways."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._base_url = settings.llm_base_url.rstrip("/")

    @property
    def configured(self) -> bool:
        return bool(self._settings.llm_enabled and self._base_url and self._settings.llm_model)

    async def health(self) -> dict[str, Any]:
        if not self.configured:
            return {"configured": False, "reachable": False, "model": self._settings.llm_model}
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                response = await client.get(
                    f"{self._base_url}/models",
                    headers=self._headers(),
                )
                if response.status_code == httpx.codes.NOT_FOUND:
                    # Some OpenAI-compatible gateways expose chat completions
                    # but intentionally omit /models. Probe the chat route
                    # without a prompt so health reflects the route Brain uses.
                    probe = await client.post(
                        f"{self._base_url}/chat/completions",
                        headers=self._headers(),
                        json={
                            "model": self._settings.llm_model,
                            "messages": [],
                            "stream": False,
                        },
                    )
                    if 400 <= probe.status_code < 500 and probe.status_code not in {
                        httpx.codes.UNAUTHORIZED,
                        httpx.codes.FORBIDDEN,
                        httpx.codes.NOT_FOUND,
                    }:
                        return {
                            "configured": True,
                            "reachable": True,
                            "model": self._settings.llm_model,
                            "models": [self._settings.llm_model],
                        }
                response.raise_for_status()
                payload = response.json()
            return {
                "configured": True,
                "reachable": True,
                "model": self._settings.llm_model,
                "models": [item.get("id") for item in payload.get("data", [])[:20]],
            }
        except Exception as exc:  # health endpoint must remain available
            return {
                "configured": True,
                "reachable": False,
                "model": self._settings.llm_model,
                "error": str(exc)[:300],
            }

    async def json_chat(
        self,
        system_prompt: str,
        user_payload: dict[str, Any],
        *,
        max_tokens: int | None = None,
    ) -> LlmResult | None:
        if not self.configured:
            return None

        body: dict[str, Any] = {
            "model": self._settings.llm_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(user_payload, ensure_ascii=False, separators=(",", ":"), default=str),
                },
            ],
            "temperature": self._settings.llm_temperature,
            "max_tokens": max_tokens or self._settings.llm_max_tokens,
            "stream": False,
        }
        if self._settings.llm_json_response_format:
            body["response_format"] = {"type": "json_object"}
        body["chat_template_kwargs"] = {"enable_thinking": self._settings.llm_enable_thinking}

        started = time.perf_counter()
        try:
            response = await self._post(body)
        except httpx.HTTPStatusError as exc:
            # Some OpenAI-compatible servers reject response_format or chat_template_kwargs.
            if exc.response.status_code in {400, 404, 422}:
                body.pop("response_format", None)
                body.pop("chat_template_kwargs", None)
                try:
                    response = await self._post(body)
                except Exception as retry_exc:
                    logger.warning("LLM retry failed: %s", retry_exc)
                    return None
            else:
                logger.warning("LLM request failed: %s", exc)
                return None
        except Exception as exc:
            logger.warning("LLM request failed: %s", exc)
            return None

        latency_ms = int((time.perf_counter() - started) * 1000)
        try:
            payload = response.json()
            message = payload["choices"][0]["message"]
            content = message.get("content")
            if not content:
                # Qwen-compatible servers may place the answer in the
                # reasoning field when content is empty.
                content = message.get("reasoning_content")
            parsed = self._extract_json(content)
            usage = payload.get("usage") or {}
            return LlmResult(
                data=parsed,
                model=str(payload.get("model") or self._settings.llm_model),
                prompt_tokens=int(usage.get("prompt_tokens") or 0),
                completion_tokens=int(usage.get("completion_tokens") or 0),
                latency_ms=latency_ms,
            )
        except Exception as exc:
            logger.warning("LLM returned invalid JSON: %s", exc)
            return None

    async def _post(self, body: dict[str, Any]) -> httpx.Response:
        timeout = httpx.Timeout(
            connect=min(10.0, self._settings.llm_timeout_seconds),
            read=self._settings.llm_timeout_seconds,
            write=min(30.0, self._settings.llm_timeout_seconds),
            pool=min(10.0, self._settings.llm_timeout_seconds),
        )
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"{self._base_url}/chat/completions",
                headers=self._headers(),
                json=body,
            )
            response.raise_for_status()
            return response

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._settings.llm_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "NT-Shield-Brain/0.1",
        }

    @staticmethod
    def _extract_json(content: Any) -> dict[str, Any]:
        if isinstance(content, dict):
            return content
        text = str(content or "").strip()
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE).strip()
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
        try:
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError("JSON root must be an object")
            return value
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start < 0 or end <= start:
                # Keep a useful narrative answer when the model ignores the
                # JSON contract. The deterministic engine still supplies all
                # safety-critical fields; the narrative is retained in the
                # final English summary instead of discarding the LLM call.
                logger.warning("LLM returned narrative instead of JSON; preserving narrative summary")
                return {"summary_en": text}
            value = json.loads(text[start : end + 1])
            if not isinstance(value, dict):
                raise ValueError("JSON root must be an object")
            return value
