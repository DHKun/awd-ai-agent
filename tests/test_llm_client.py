"""test_llm_client — 双后端真实 HTTP 路径测试（本地 mock 服务，不依赖外部 API）。

覆盖 awd/llm/client.py 的 openai/ollama 请求构造与响应解析（原 56% 覆盖）：
- Ollama：format:"json" 传参 + 响应解析 + HTTP 错误 → LLMError
- OpenAI 兼容：response_format json_object 传参 + 解析
- 网络拒绝 → LLMError（不挂死）
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

import pytest

from awd.config import LLMConfig
from awd.llm.client import LLMClient, LLMError


class OllamaMock(BaseHTTPRequestHandler):
    """Ollama /api/chat 假服务：校验 format:"json" 传参。"""

    last_payload: dict = {}
    status_to_return = 200

    def log_message(self, *a):
        pass

    def do_POST(self):
        # 写类属性（self.xxx = 只会创建实例属性，测试读不到）
        type(self).last_payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.status_to_return != 200:
            self.send_response(self.status_to_return)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({"message": {"content": json.dumps({"test_cases": []})}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class OpenAIMock(BaseHTTPRequestHandler):
    """OpenAI /chat/completions 假服务：校验 response_format 传参。"""

    last_payload: dict = {}

    def log_message(self, *a):
        pass

    def do_POST(self):
        type(self).last_payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        body = json.dumps({
            "choices": [{"message": {"content": json.dumps({"test_cases": []})}}]
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def ollama_url():
    srv = HTTPServer(("127.0.0.1", 0), OllamaMock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def openai_url():
    srv = HTTPServer(("127.0.0.1", 0), OpenAIMock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.mark.asyncio
async def test_ollama_sends_format_json_and_parses(ollama_url):
    """Ollama 后端：请求体必须带 format:"json"，响应 content 再解析为对象。"""
    cfg = LLMConfig(backend="ollama")
    cfg.ollama.base_url = ollama_url
    cfg.ollama.model = "test-model"
    client = LLMClient(cfg)

    out = await client.chat_json("sys", "user", timeout=5.0)
    assert out == {"test_cases": []}

    sent = OllamaMock.last_payload
    assert sent["format"] == "json", "Ollama 必须用 format:'json' 而非 response_format"
    assert sent["model"] == "test-model"
    assert sent["messages"][0]["role"] == "system"
    assert sent["stream"] is False


@pytest.mark.asyncio
async def test_openai_sends_response_format_and_parses(openai_url):
    """OpenAI 兼容后端：请求体必须带 response_format json_object。"""
    cfg = LLMConfig(backend="openai")
    cfg.openai.base_url = openai_url
    cfg.openai.model = "test-model"
    cfg.openai.api_key = "sk-test"
    client = LLMClient(cfg)

    out = await client.chat_json("sys", "user", timeout=5.0)
    assert out == {"test_cases": []}

    sent = OpenAIMock.last_payload
    assert sent["response_format"] == {"type": "json_object"}
    assert sent["model"] == "test-model"
    assert sent["messages"][1]["content"] == "user"


@pytest.mark.asyncio
async def test_ollama_http_error_raises_llmerror(ollama_url):
    """Ollama 返回 500 → LLMError（上层走字典降级）。"""
    OllamaMock.status_to_return = 500
    try:
        cfg = LLMConfig(backend="ollama")
        cfg.ollama.base_url = ollama_url
        client = LLMClient(cfg)
        with pytest.raises(LLMError, match="failed"):
            await client.chat_json("s", "u", timeout=5.0)
    finally:
        OllamaMock.status_to_return = 200


@pytest.mark.asyncio
async def test_ollama_connection_refused_raises_llmerror():
    """连接拒绝 → LLMError（快速失败，不挂死）。"""
    cfg = LLMConfig(backend="ollama")
    cfg.ollama.base_url = "http://127.0.0.1:59907"
    client = LLMClient(cfg)
    with pytest.raises(LLMError):
        await client.chat_json("s", "u", timeout=5.0)


@pytest.mark.asyncio
async def test_llm_hard_timeout_not_hanging():
    """硬超时：后端挂死时 wait_for 切断（0.3s 内抛 LLMError）。

    注意：BaseHTTPServer 是单线程 —— handler sleep 会阻塞 serve_forever，
    因此用 ThreadingHTTPServer，请求在独立线程挂死，shutdown 不被拖住。
    """

    class HungHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            import time
            time.sleep(30)  # 挂死（daemon 线程，测试结束即消亡）

    srv = ThreadingHTTPServer(("127.0.0.1", 0), HungHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_port

    cfg = LLMConfig(backend="ollama")
    cfg.ollama.base_url = f"http://127.0.0.1:{port}"
    client = LLMClient(cfg)
    with pytest.raises(LLMError, match="timeout"):
        await client.chat_json("s", "u", timeout=0.3)
    srv.shutdown()
