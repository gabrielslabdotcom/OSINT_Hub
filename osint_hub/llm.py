"""Thin LLM client: local Ollama by default, Anthropic when a key is present."""

from __future__ import annotations

import importlib.util
import json

import httpx

from osint_hub.config import Settings


def claude_sdk_available() -> bool:
    return importlib.util.find_spec("anthropic") is not None


def query_llm(
    prompt: str,
    provider: str,
    settings: Settings,
    *,
    system: str | None = None,
) -> str:
    provider = provider.lower().strip()
    if provider == "local":
        return _query_ollama(prompt, settings, system=system)
    if provider == "claude":
        return _query_claude(prompt, settings, system=system)
    raise ValueError(f"Unknown provider {provider!r}. Use 'local' or 'claude'.")


def _query_ollama(prompt: str, settings: Settings, *, system: str | None = None) -> str:
    url = f"{settings.ollama_base_url}/api/chat"
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    payload = {
        "model": settings.ollama_model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.2},
    }
    with httpx.Client(timeout=settings.ollama_timeout) as client:
        response = client.post(url, json=payload, headers=settings.ollama_headers())
        if response.is_error:
            detail = (response.text or response.reason_phrase)[:300]
            raise RuntimeError(f"Ollama HTTP {response.status_code} for {url}: {detail}")
        data = response.json()
    message = data.get("message") if isinstance(data, dict) else None
    text = message.get("content") if isinstance(message, dict) else None
    if not text:
        raise RuntimeError(f"Ollama returned no response text: {data!r}"[:400])
    return str(text)


def _json_complete(text: str) -> bool:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end <= start:
        return False
    try:
        json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError:
        return False
    return True


def _message_text(message: object) -> str:
    chunks: list[str] = []
    for block in getattr(message, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            chunks.append(text)
    return "\n".join(chunks)


def _query_claude(prompt: str, settings: Settings, *, system: str | None = None) -> str:
    if not settings.has_claude:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError("Anthropic SDK is not installed. Run: pip install -e '.[web]'") from exc

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    kwargs: dict = {
        "model": settings.anthropic_model,
        "max_tokens": settings.anthropic_max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system
    message = client.messages.create(**kwargs)
    text = _message_text(message)
    if not text:
        raise RuntimeError("Claude returned empty content")
    if str(getattr(message, "stop_reason", "") or "") == "max_tokens" and not _json_complete(text):
        follow = client.messages.create(
            **{
                **{k: v for k, v in kwargs.items() if k != "messages"},
                "messages": [
                    {"role": "user", "content": prompt},
                    {"role": "assistant", "content": text},
                ],
            }
        )
        extra = _message_text(follow)
        if extra:
            text = text + extra
        if str(getattr(follow, "stop_reason", "") or "") == "max_tokens" and not _json_complete(text):
            raise RuntimeError(
                f"Claude hit the output cap ({settings.anthropic_max_tokens} tokens) twice; "
                "raise ANTHROPIC_MAX_TOKENS or retry Analyze."
            )
    return text
