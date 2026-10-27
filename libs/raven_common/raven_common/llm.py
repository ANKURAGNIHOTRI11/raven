"""OpenAI-compatible client for the local vLLM server, with retries and a
strict JSON-object contract."""
from __future__ import annotations

import orjson
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, base_url: str, model: str, timeout: float = 180.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._client = httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=12))
    async def complete(
        self,
        system: str,
        user: str,
        temperature: float = 0.0,
        max_tokens: int = 1400,
        json_object: bool = True,
    ) -> str:
        body: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_object:
            body["response_format"] = {"type": "json_object"}
        r = await self._client.post(f"{self.base_url}/chat/completions", json=body)
        if r.status_code >= 400:
            raise LLMError(f"{r.status_code}: {r.text[:300]}")
        data = r.json()
        return data["choices"][0]["message"]["content"]

    async def complete_json(self, system: str, user: str, **kw) -> dict:
        raw = await self.complete(system, user, **kw)
        text = raw.strip()
        if text.startswith("```"):
            text = text.strip("`")
            text = text.split("\n", 1)[-1] if text.lower().startswith("json") else text
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1:
            raise LLMError(f"no JSON object in model output: {text[:200]}")
        return orjson.loads(text[start : end + 1])

    async def healthy(self) -> bool:
        try:
            r = await self._client.get(f"{self.base_url}/models", timeout=10)
            return r.status_code == 200
        except Exception:
            return False
