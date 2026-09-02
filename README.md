# AWD AI Agent

AWD（Attack With Defense）攻防竞赛的半自动化智能 Agent：打破"写死脚本"模式，构建「侦察 → 智能打点 → Flag 提取提交 → 自防御」闭环流水线。

> ⚠️ **仅用于授权学习/竞赛环境**。目标以 `config/settings.yaml` 中 `scope: scoped` 声明的网段为界，越界即拒绝（`ScopeGuard`）。

## 核心特性

| 特性 | 实现 |
|---|---|
| **并发与优雅降级** | `asyncio.Semaphore + gather(return_exceptions=True)`，单点超时/异常只降级该目标，绝不阻塞全局调度 |
| **上下文工程** | 原始 HTTP 响应 → 结构化 `TargetContext`，token 预算内压缩（实测 ≥98% 压缩率，BPE 近似） |
| **LLM 防幻觉四原则** | 证据命中才下发（`evidence_refs` 必须命中原文）、LLM 只提假设（执行器才定 `confirmed`）、显式重试上限、Strict JSON + jsonschema 校验 |
| **LLM 硬超时 + 字典降级** | 每次调用 `wait_for` 硬超时，超时/网络错误自动降级内置字典，绝不拖垮调度 |
| **动态语义字典** | `(路由, 参数, 取值模式)` 三元组建桶；从 flag 格式/补丁 diff 挖掘高频 token |
| **自防御** | 文件哈希监控（`(size, mtime, sha256)` 基线轮询，仅变化段喂 LLM）+ 轻量 WAF（yaml 规则热加载）+ 回滚恢复 |

## 架构

```
config → scheduler.spawn(targets)
  → probe (asyncio 并发) → context_builder 压缩成 TargetContext
  → llm.analyze(ctx) → schema 校验通过 → payload_gen 生成用例
  → runner 执行 → evidence 回流 → Finding
  → flag_submit 提取+提交 → 成功记录
  → DEFENSE: hash_monitor 基线 + waf 热加载
  → 回到 RECON（新路由/补丁后重打）
```

状态机：`RECON → ANALYZE → EXPLOIT → EXTRACT → SUBMIT`，EXPLOIT 子状态 `QUEUED → RUNNING → VERIFIED/CANDIDATE/FAILED`；单目标失败达 cap 进 `BLACKLISTED` 防死循环。

```
awd-ai-agent/
├── config/settings.yaml     # 唯一可改配置（目标/并发/超时/LLM/阈值）
├── rules/waf_rules.yaml     # 轻量 WAF 规则（热加载）
├── dicts/                   # 语义字典（漏洞关键词/常见参数）
├── awd/
│   ├── config.py            # yaml 读取 + ${ENV} 展开 + ScopeGuard
│   ├── models.py            # TargetContext/Finding/AgentTask/DefenseState
│   ├── scheduler.py         # asyncio 并发池（Semaphore + 降级）
│   ├── store.py             # aiosqlite 持久化（jobs/results/state）
│   ├── main.py              # CLI 入口（run/recon/defense/report）
│   ├── recon/               # probe / fingerprint / context_builder
│   ├── llm/                 # client / schema / analyze / prompt
│   ├── exploit/             # payload_gen / runner / flag_submit
│   └── defense/             # hash_monitor / waf / rollback
└── tests/                   # 56 项测试（scheduler/context/schema/exploit/waf）
```

## 快速开始

要求 Python 3.11+。

```bash
python3.11 -m venv .venv
.venv/bin/pip install httpx pydantic aiosqlite loguru watchdog openai jsonschema pyyaml pytest pytest-asyncio
```

### 配置

编辑 `config/settings.yaml`：

```yaml
scope:
  mode: scoped
  in_scope: ["127.0.0.1", "10.0.0.0/8"]   # 授权边界，越界拒绝

targets:
  - "http://10.0.0.5:8080"

llm:
  backend: ollama          # openai | ollama
  ollama:
    base_url: ${OLLAMA_BASE_URL:-http://127.0.0.1:11434}
    model: ${OLLAMA_MODEL:-qwen2.5:7b}
```

LLM 端点支持 `${ENV_VAR:-default}` 环境变量展开。**LLM 不可用不阻塞**：所有调用有硬超时，失败自动降级内置字典照常打点。

### 运行

```bash
.venv/bin/python -m awd.main run            # 全流程：侦察 → 打点 → flag
.venv/bin/python -m awd.main recon          # 仅侦察，打印 TargetContext
.venv/bin/python -m awd.main defense        # 防御端：基线 + 哈希轮询（Ctrl-C 退出）
.venv/bin/python -m awd.main report         # findings/降级目标/flag 台账汇总
.venv/bin/python -m awd.main run --targets http://10.0.0.9:80  # 临时覆盖目标（仍受 scope 约束）
```

### 测试

```bash
.venv/bin/python -m pytest tests/ -q
# 56 passed
```

测试不依赖真实网络/LLM：调度与执行用假目标/`httpx.MockTransport` 模拟。

## 验收指标（实测）

| 指标 | 设计目标 | 实测 |
|---|---|---|
| 50 目标含 3 超时 | 整体完成且坏目标降级记录 | ✅ 47 ok / 3 degraded，全部落库 |
| 100 目标并发 | < 60s | ✅ 0.10s（~58000 targets/min） |
| 上下文压缩 | ≥ 98% | ✅ 120KB raw → 预算内 TargetContext |
| LLM 输出 | 100% 合法 JSON | ✅ jsonschema 校验，非法重试/丢弃 |
| 防幻觉 | evidence 命中才下发 | ✅ 不命中整条丢弃 + confidence 钳 0.89 |
| 端到端 | 靶机提交 flag | ✅ 假 ThinkPHP 靶机 → confirmed + flag 提取 |
| WAF/校验单测 | 通过 | ✅ 含热加载/作用域/篡改检出/回滚 |

## 关键设计

### AI 防幻觉四原则

1. **只有证据才让 LLM 下结论** — `evidence_refs` 必须命中 `recon_evidence` 原文，否则整条 test_case 丢弃（`llm/schema.py` 的 grounding 过滤）。
2. **LLM 只是假设生成器** — 未经执行验证不得 `confirmed`；confidence 钳到 0.89 上限，只有执行器命中真实信号（`uid=`、`root:x:0:0:`、`flag{...}` 等）才升级 `confirmed`。
3. **显式重试上限** — `retry_cap=3` + `analysis_attempts_cap`，超限放弃该目标走下一个。
4. **Strict JSON + 硬超时** — OpenAI 兼容用 `response_format={"type":"json_object"}`，Ollama 用 `format:"json"`（两套参数在 `llm/client.py` 分别处理）；每次调用内层 `wait_for` 硬超时。

### 失败语义

- **网络错误/超时** → 计入失败次数，达 `exploit_failure_cap` 进 `BLACKLISTED`（防死循环）
- **HTTP 404** → 用例不命中但目标存活，**不**计入失败（避免误拉黑）
- **LLM 降级** → 内置字典用例（`generated_by: dict`），照常执行

## 规划文档

- [`agent.md`](agent.md) — 定位 / 技术选型 / 状态机 / AI 约束 / 边界
- [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — 目录架构 / 数据 Schema / 分阶段路线图
- [`AI_INIT.md`](AI_INIT.md) — 下游 AI 初始指令

## License

MIT（如需商用请自备授权环境与合规审查）。
