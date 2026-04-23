"""
nano_swarm/llm_client.py
─────────────────────────
Unified LLM client. Supports three backends:

  deepseek  — DeepSeek API (api.deepseek.com)
               OpenAI-compatible endpoint, so we use the /chat/completions format.
               This is the primary backend: DeepSeek V3 is the orchestrating model.

  anthropic — Anthropic API (api.anthropic.com)
               Uses the /v1/messages format. Fallback or alternative backend.

  ollama    — Local Ollama server (self-hosted, Docker sidecar)
               Uses the /api/chat format. Useful for offline or cost-controlled runs.

All three return the same LLMResponse object so callers don't care which
backend is active.

Usage:
    from nano_swarm.llm_client import get_client
    client = get_client()
    response = client.chat(system="You are...", user="Analyze this...")
    print(response.text)
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Optional

import requests

from .config import settings

log = logging.getLogger(__name__)


# ── Response container ────────────────────────────────────────────────────────

@dataclass
class LLMResponse:
    text: str                    # raw model output
    model: str                   # model identifier actually used
    input_tokens: int
    output_tokens: int

    def as_json(self) -> dict:
        """
        Parse the response text as JSON.
        Strips markdown code fences if the model added them.
        Raises ValueError with a clear message on parse failure.
        """
        text = self.text.strip()

        # Strip ```json ... ``` or ``` ... ``` fences
        if text.startswith("```"):
            lines = text.splitlines()
            # Drop first line (```json or ```) and last line (```)
            inner = lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
            text = "\n".join(inner).strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Model returned non-JSON text.\n"
                f"Parse error: {exc}\n"
                f"Raw text (first 500 chars):\n{self.text[:500]}"
            ) from exc


# ── Backend implementations ───────────────────────────────────────────────────

class _DeepSeekClient:
    """
    DeepSeek API via its OpenAI-compatible endpoint.
    Model: deepseek-chat (DeepSeek V3) or deepseek-reasoner (DeepSeek R1).
    """

    def __init__(self) -> None:
        self._api_key = settings.deepseek_api_key
        self._model = settings.deepseek_model
        self._base = settings.deepseek_api_base.rstrip("/")
        self._url = f"{self._base}/chat/completions"

    def chat(
        self,
        system: str,
        user: str,
        max_tokens: int = 4096,
        temperature: float = 0.2,
        retries: int = 3,
    ) -> LLMResponse:
        payload = {
            "model": self._model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        }

        for attempt in range(1, retries + 1):
            try:
                resp = requests.post(
                    self._url,
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=120,
                )
                resp.raise_for_status()
                data = resp.json()

                choice = data["choices"][0]
                usage = data.get("usage", {})
                return LLMResponse(
                    text=choice["message"]["content"],
                    model=data.get("model", self._model),
                    input_tokens=usage.get("prompt_tokens", 0),
                    output_tokens=usage.get("completion_tokens", 0),
                )

            except requests.HTTPError as exc:
                log.warning("DeepSeek HTTP error (attempt %d/%d): %s", attempt, retries, exc)
                if exc.response is not None and exc.response.status_code in (400, 401, 403):
                    raise  # non-retryable
            except (requests.ConnectionError, requests.Timeout) as exc:
                log.warning("DeepSeek connection error (attempt %d/%d): %s", attempt, retries, exc)

            if attempt < retries:
                time.sleep(2 ** attempt)

        raise RuntimeError(f"DeepSeek API failed after {retries} attempts")


class _AnthropicClient:
    """
    Anthropic API using the /v1/messages endpoint.
    Used as a fallback or when LLM_BACKEND=anthropic.
    """

    def __init__(self) -> None:
        self._api_key = settings.anthropic_api_key
        self._model = settings.anthropic_model
        self._url = "https://api.anthropic.com/v1/messages"

    def chat(
        self,
        system: str,
        user: str,
        max_tokens: int = 4096,
        temperature: float = 0.2,
        retries: int = 3,
    ) -> LLMResponse:
        payload = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }

        for attempt in range(1, retries + 1):
            try:
                resp = requests.post(
                    self._url,
                    headers={
                        "x-api-key": self._api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=120,
                )
                resp.raise_for_status()
                data = resp.json()

                content_blocks = data.get("content", [])
                text = "".join(
                    block.get("text", "")
                    for block in content_blocks
                    if block.get("type") == "text"
                )
                usage = data.get("usage", {})
                return LLMResponse(
                    text=text,
                    model=data.get("model", self._model),
                    input_tokens=usage.get("input_tokens", 0),
                    output_tokens=usage.get("output_tokens", 0),
                )

            except requests.HTTPError as exc:
                log.warning("Anthropic HTTP error (attempt %d/%d): %s", attempt, retries, exc)
                if exc.response is not None and exc.response.status_code in (400, 401, 403):
                    raise
            except (requests.ConnectionError, requests.Timeout) as exc:
                log.warning("Anthropic connection error (attempt %d/%d): %s", attempt, retries, exc)

            if attempt < retries:
                time.sleep(2 ** attempt)

        raise RuntimeError(f"Anthropic API failed after {retries} attempts")


class _OllamaClient:
    """
    Local Ollama server. Use when running entirely offline or to avoid API costs.
    Model must be pulled first: `ollama pull deepseek-r1:7b`
    """

    def __init__(self) -> None:
        self._host = settings.ollama_host.rstrip("/")
        self._model = settings.ollama_model
        self._url = f"{self._host}/api/chat"

    def chat(
        self,
        system: str,
        user: str,
        max_tokens: int = 4096,
        temperature: float = 0.2,
        retries: int = 3,
    ) -> LLMResponse:
        payload = {
            "model": self._model,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        }

        for attempt in range(1, retries + 1):
            try:
                resp = requests.post(self._url, json=payload, timeout=300)
                resp.raise_for_status()
                data = resp.json()

                text = data.get("message", {}).get("content", "")
                return LLMResponse(
                    text=text,
                    model=self._model,
                    input_tokens=data.get("prompt_eval_count", 0),
                    output_tokens=data.get("eval_count", 0),
                )

            except (requests.ConnectionError, requests.Timeout) as exc:
                log.warning("Ollama error (attempt %d/%d): %s", attempt, retries, exc)

            if attempt < retries:
                time.sleep(2 ** attempt)

        raise RuntimeError(f"Ollama server at {self._host} failed after {retries} attempts")


# ── Public factory ────────────────────────────────────────────────────────────

# Module-level singleton — instantiated once, reused everywhere
_client: Optional[_DeepSeekClient | _AnthropicClient | _OllamaClient] = None


def get_client() -> _DeepSeekClient | _AnthropicClient | _OllamaClient:
    """
    Return the configured LLM client singleton.

    The backend is chosen by LLM_BACKEND in .env (or environment).
    Call this wherever you need to make a model request.
    """
    global _client
    if _client is not None:
        return _client

    backend = settings.llm_backend
    if backend == "deepseek":
        _client = _DeepSeekClient()
    elif backend == "anthropic":
        _client = _AnthropicClient()
    elif backend == "ollama":
        _client = _OllamaClient()
    else:
        raise ValueError(
            f"Unknown LLM_BACKEND={backend!r}. "
            "Set LLM_BACKEND to 'deepseek', 'anthropic', or 'ollama' in .env"
        )

    log.info("LLM client: %s (model=%s)", backend, _client._model)
    return _client
