# AWD 智能攻防半自动化 Agent — 工程实施计划

> 项目定位：打破"写死脚本"模式，构建「侦察→智能打点→Flag 提取提交→自防御」的闭环流水线。
> 本目录为**规划层文档**（无业务代码），由下游 AI 依据本计划 + `AI_INIT.md` 落地实现。

---

## 1. 技术栈与目录架构

**选型：Python 3.11+ / asyncio / httpx / aiosqlite / pydantic v2 / loguru / watchdog / openai 兼容 SDK（含 Ollama 回退）/ jsonschema（LLM 输出结构校验）。**
> 版本提示：Python 3.11+（asyncio 稳定）；`httpx>=0.27`；`pydantic>=2.7`；`aiosqlite>=0.20`。均按月内可用。LLM 的 JSON 模式：OpenAI 兼容 `response_format={"type":"json_object"}`，Ollama `format:"json"`，两者 API 略有差异，需在 `client.py` 里按后端分别传参。

```
awd-ai-agent/
├── IMPLEMENTATION_PLAN.md   # 本计划
├── AI_INIT.md               # 下游 AI 直接粘贴指令
├── config/
│   └── settings.yaml        # 目标/并发/超时/LLM端点/阈值（唯一可改配置）
├── rules/
│   └── waf_rules.yaml       # 轻量 WAF 规则（热加载）
├── dicts/
│   ├── vuln_words.txt       # 语义字典（漏洞关键词）
│   └── params.txt           # 常见参数名
├── awd/
│   ├── __init__.py
│   ├── config.py            # 读取 settings.yaml, 校验, 生成 Settings 对象
│   ├── models.py            # TargetContext / Finding / AgentTask / DefenseState（与 agent.md §4 对齐）
│   ├── scheduler.py         # asyncio 并发池（Semaphore + gather + 优雅降级）
│   ├── store.py             # aiosqlite 持久化（jobs/results/state）
│   ├── main.py              # 入口 CLI
│   ├── recon/
│   │   ├── __init__.py
│   │   ├── probe.py         # 单目标异步探测（http/https, 兜底 raw）
│   │   ├── fingerprint.py   # 指纹归一化 server/框架/CMS
│   │   └── context_builder.py# raw → TargetContext 压缩（token 预算）
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── client.py        # OpenAI/Ollama 双后端统一封装
│   │   ├── schema.py        # Strict JSON 输出 Schema + 防幻觉/防死循环校验
│   │   ├── analyze.py       # 未知指纹分析 → 定向测试用例
│   │   └── prompt.py        # System Prompt 模板
│   ├── exploit/
│   │   ├── __init__.py
│   │   ├── payload_gen.py   # 动态语义字典 + 模板化 payload
│   │   ├── runner.py        # 用例执行（超时/重试/证据提取）
│   │   └── flag_submit.py   # flag 正则提取 + 提交器
│   └── defense/
│       ├── __init__.py
│       ├── hash_monitor.py  # 文件哈希监控（asyncio 轮询，差异仅喂变化段）
│       ├── waf.py           # yaml 热加载规则匹配
│       └── rollback.py      # 降级/恢复编排
└── tests/
    ├── test_scheduler.py    # 并发 + 坏目标降级
    ├── test_context.py      # 压缩率
    └── test_schema.py       # 防幻觉校验
```

---

## 2. 核心数据结构与状态机

### TargetContext（模块间唯一上下文）
```jsonc
{
  "target_id": "t-001",
  "url": "http://10.0.0.5:8080",
  "fingerprint": {"server": "nginx", "framework": "thinkphp", "version_hint": "5.0.x"},
  "routes": [{"path": "/index.php", "method": "GET", "status": 200, "params": ["s"]}],
  "recon_evidence": ["<对原文的摘要片段，evidence_refs 必须可命中>"],
  "risk_probe": {"dir_listing": true, "debug_page": false},
  "tokens_estimate": 1800
}
```

### Finding（打点结果，含真实证据）
```jsonc
{
  "id": "f-001", "target_id": "t-001",
  "type": "rce|sqli|file_read|debug|weak_auth",
  "payload": "?s=index/\\think\\app/invokefunction...",
  "evidence": "id=www-data (uid=33)",
  "confidence": 0.92,
  "status": "confirmed|candidate",
  "generated_by": "llm|dict|manual"
}
```

### 状态机
```
RECON ─> ANALYZE ─> EXPLOIT ─> EXTRACT ─> SUBMIT ─┐
   │          │            │                     │
   │          └─(无证据/低置信)─> 退回 RECON(换目标) │
   │                                              │
   └──────── 定时/事件触发 ─────────────────────> DEFENSE
```
EXPLOIT 子状态：`QUEUED → RUNNING → VERIFIED/CANDIDATE/FAILED`。单目标失败 N 次自动进入 `blacklist`，防死循环。

---

## 3. 核心功能模块深度设计

### 数据流
```
config → scheduler.spawn(targets)
  → probe (asyncio 并发) → context_builder 压缩成 TargetContext
  → llm.analyze(ctx) → schema 校验通过 → payload_gen 生成用例
  → runner 执行 → evidence 回流 → Finding
  → flag_submit 提取+提交 → 成功记录
  → DEFENSE: hash_monitor 基线 + waf 热加载
  → 回到 RECON（新路由/补丁后重打）
```

### AI 交互（防幻觉四原则）
1. **只有证据才让 LLM 说结论**：`evidence_refs` 必须能命中原始上下文，否则整条 test_case 丢弃。
2. **LLM 只是假设生成器，执行器才给它"结果"**：未执行验证的证据不得标记 confirmed。
3. **显式重试上限**：`retry_cap=3`、全局 `analysis_attempts` 上限，超限即放弃该目标进入 next。
4. **strict JSON**：OpenAI 兼容用 `response_format: {"type":"json_object"}`，Ollama 用 `format:"json"`；用 `jsonschema` 校验结构，非法即重试或丢弃。
5. **LLM 硬超时 + fallback**：每次 LLM 调用设超时（如 20s），超时/网络错误走内置字典降级，绝不阻塞全局调度。

---

## 4. 关键算法

### 并发调度 + 优雅降级（验收：50 目标含 3 超时，整体完成且坏目标被降级记录）
```python
async def run_probe_pool(targets, max_concurrency=50, timeout=8.0):
    sem = asyncio.Semaphore(max_concurrency)
    queue = asyncio.Queue()
    async def worker(tid):
        async with sem:
            try:
                # wait_for 确保单目标超时可抛 TimeoutError，不阻塞全局
                ctx = await asyncio.wait_for(probe(tid), timeout=timeout)
            except asyncio.TimeoutError:
                # 首次超时只标记 failed（进 blacklist 由重试计数触达 retry_cap 决定，见状态机）
                await store.mark_state(tid, "failed", error="timeout"); return
            except Exception as e:
                log.warning(f"probe {tid} degraded: {e}")
                await store.mark_state(tid, "failed", error=str(e)); return
            await queue.put(ctx)
    await asyncio.gather(*[worker(t) for t in targets], return_exceptions=True)
```

### 动态语义字典
从 flag 格式/补丁 diff 挖掘高频 token，按 `(路由, 参数名, 取值模式)` 三元组建桶，命中优先对该桶生成 payload。

### 文件哈希监控
基线快照 → 轮询比较 `(size, mtime, sha256)`；仅将变化段喂 LLM，避免全量重算。

---

## 5. 分阶段路线图（2 周）

| 阶段 | 微任务 | Deliverables | 验收指标 |
|---|---|---|---|
| Day 1-3 | 骨架：config/models/store/scheduler；单目标探测 | 可运行 CLI，日志/状态落库 | 单目标 3s 内；无崩溃 |
| Day 4-7 | 并发池 + 上下文压缩 + LLM 分析（OpenAI/Ollama） | 并发 100+ 目标；压缩率≥98% | 100 目标 <60s；输出 100% 合法 JSON |
| Day 8-10 | 字典/payload + runner + flag 提交 | 打点链路跑通 | Demo 靶机提交 flag；错误用例不进队列 |
| Day 11-14 | 防御端 + 防幻觉校验 + 测试 | 全流程闭环 | WAF/校验单测通过 |

---

## 6. 简历亮点
1. **并发与降级**：`asyncio.Semaphore + gather(return_exceptions=True)`，单点超时/异常不阻塞全局。
2. **上下文工程**：原始 HTTP 响应 → 结构化 TargetContext，token 压缩≥98%。
3. **可控自动化**：语义字典 + 定向 payload，配合"证据命中才下发"校验防幻觉。

> 量化指标（压缩率 98%、1000+/min 吞吐、2KB 上下文等）为**设计目标**，实现阶段必须实测替换为真实值后写入简历。
