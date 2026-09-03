"""LLM 双后端统一封装（plan: client.py）。

- 所有 LLM 调用统一走这里，业务模块不直接 import 厂商 SDK。
- OpenAI 兼容：`response_format={"type": "json_object"}` 强制 JSON 模式。
- Ollama：`format: "json"`（原生参数）。
- 每次调用 asyncio.wait_for(llm_timeout) 硬超时；超时/网络错误抛 LLMError，
  由上层（analyze）走内置字典降级，绝不阻塞全局调度。
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

from loguru import logger

from awd.config import LLMConfig


class LLMError(RuntimeError):
    """LLM 调用失败（超时/网络/非法输出）。上层据此走降级。"""


class LLMClient:
    """OpenAI/Ollama 双后端。调用侧只关心 chat_json(prompt) -> dict。"""

    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self._openai = None  # 惰性创建：避免未用时也拉起 SDK

    # ---- 后端选择 -----------------------------------------------------------

    def _client(self):
        if self.cfg.backend == "openai":
            if self._openai is None:
                from openai import AsyncOpenAI  # 唯一允许 import SDK 的地方
                self._openai = AsyncOpenAI(
                    base_url=self.cfg.openai.base_url,
                    api_key=self.cfg.openai.api_key or "sk-EMPTY",
                )
            return self._openai
        return None  # ollama 走 httpx 直连 REST

    async def chat_json(
        self,
        system: str,
        user: str,
        *,
        timeout: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> dict:
        """一次调用 → JSON dict。失败（超时/网络/解析）抛 LLMError。"""
        t = timeout or 20.0
        try:
            if self.cfg.backend == "openai":
                raw = await asyncio.wait_for(self._chat_openai(system, user, t, max_tokens), timeout=t)
            else:
                raw = await asyncio.wait_for(self._chat_ollama(system, user, t, max_tokens), timeout=t)
        except LLMError:
            raise
        except asyncio.TimeoutError as e:  # 内层 wait_for 硬超时
            raise LLMError(f"llm timeout after {t}s") from e
        except TimeoutError as e:  # httpx 层超时（httpx.TimeoutException 是其子类）
            raise LLMError(f"llm timeout after {t}s") from e
        except Exception as e:  # noqa: BLE001 — 网络等一切失败统一走降级
            raise LLMError(f"llm call failed: {type(e).__name__}: {e}") from e
        return self._parse_json(raw)

    # ---- OpenAI 兼容后端 ------------------------------------------------------

    async def _chat_openai(self, system: str, user: str, timeout: float, max_tokens: Optional[int]) -> str:
        import asyncio

        client = self._client()
        kwargs: dict[str, Any] = {
            "model": self.cfg.openai.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.cfg.temperature,
            # OpenAI 兼容 JSON 模式（与 Ollama 的 format:"json" 是两套参数）
            "response_format": {"type": "json_object"},
        }
        if max_tokens:
            kwargs["max_tokens"] = max_tokens
        resp = await asyncio.wait_for(client.chat.completions.create(**kwargs), timeout=timeout)
        return resp.choices[0].message.content or ""

    # ---- Ollama 后端（REST 直连，不经 SDK） -----------------------------------

    async def _chat_ollama(self, system: str, user: str, timeout: float, max_tokens: Optional[int]) -> str:
        import httpx

        payload: dict[str, Any] = {
            "model": self.cfg.ollama.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            # Ollama 原生 JSON 模式参数（区别于 OpenAI 的 response_format）
            "format": "json",
            "options": {"temperature": self.cfg.temperature},
        }
        if max_tokens:
            payload["options"]["num_predict"] = max_tokens
        async with httpx.AsyncClient(timeout=timeout) as http:
            resp = await http.post(
                f"{self.cfg.ollama.base_url.rstrip('/')}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
        return data.get("message", {}).get("content", "")

    # ---- 输出解析 -------------------------------------------------------------

    @staticmethod
    def _parse_json(raw: str) -> dict:
        """strict JSON：只允许合法 JSON 对象，剥掉可能的 markdown 围栏。"""
        text = raw.strip()
        if text.startswith("```"):
            # 剥 ```json ... ``` 围栏（Ollama format:"json" 偶发仍带围栏）
            lines = text.splitlines()
            body = [ln for ln in lines if not ln.strip().startswith("```")]
            text = "\n".join(body).strip()
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            logger.debug("llm output not json: {}", text[:200])
            raise LLMError(f"llm output is not valid json: {e}") from e
        if not isinstance(obj, dict):
            raise LLMError("llm output is not a json object")
        return obj
