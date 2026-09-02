# agent.md — AWD 智能攻防半自动化 Agent

> 本文件是**规划与约束层**，不含业务代码。下一阶段 AI 依据它 + `IMPLEMENTATION_PLAN.md` 直接开工，`AI_INIT.md` 是可直接粘贴的初始化指令。

## 1. 定位
打破"写死脚本"模式，构建「侦察 → 智能打点 → Flag 提取提交 → 自防御」闭环流水线。多线程探测 + 未知指纹抓上下文交 LLM 生成定向用例 + 动态语义字典 + 文件哈希监控与轻量 WAF。

## 2. 技术选型
- **语言/运行时**：Python 3.11+
- **核心库**：asyncio（并发）、httpx（异步 HTTP）、aiosqlite（状态落库）、pydantic v2（Schema）、loguru（日志）、watchdog（配置热加载）、openai 兼容 SDK（含 Ollama 本地回退）
- **LLM**：后端可切换 `openai | ollama`，强制 strict JSON；OpenAI 兼容接口直接用 `response_format: {"type":"json_object"}`，Ollama 用 `format: "json"`。

## 3. 目录架构（模块落位标记）
```
awd-ai-agent/
├── IMPLEMENTATION_PLAN.md   # 工程实施计划
├── AI_INIT.md               # 下游 AI 初始指令（可直接粘贴）
├── agent.md                 # 本文件
├── config/settings.yaml     # 唯一可改配置（目标/并发/超时/LLM）
├── rules/waf_rules.yaml     # 轻量 WAF 规则（热加载）
├── dicts/                   # 语义字典（vuln_words / params）
├── awd/                     # 主包：
│   ├── config.py            # 读 settings.yaml → Settings
│   ├── models.py            # TargetContext / Finding / AgentTask / DefenseState
│   ├── scheduler.py         # asyncio 并发池（Semaphore + 降级）
│   ├── store.py             # aiosqlite 持久化
│   ├── main.py              # CLI 入口
│   ├── recon/               # probe / fingerprint / context_builder
│   ├── llm/                 # client / schema / analyze / prompt
│   ├── exploit/             # payload_gen / runner / flag_submit
│   └── defense/             # hash_monitor / waf / rollback
└── tests/                   # test_scheduler / test_context / test_schema
```

## 4. 状态机
```
RECON ─> ANALYZE ─> EXPLOIT ─> EXTRACT ─> SUBMIT ─┐
   │          │            │                      │
   │          └─(无证据/低置信)─> 退回 RECON(换目标) │
   │                                               │
   └──────── 定时/事件触发 ────────────────────> DEFENSE
```
EXPLOIT 子状态 `QUEUED→RUNNING→VERIFIED/CANDIDATE/FAILED`；单目标失败 N 次进 `BLACKLISTED` 防死循环。

## 5. AI 交互硬约束
- **只有证据才让 LLM 下结论**：`evidence_refs` 必须命中原始上下文，否则整条 test_case 丢弃。
- **LLM 只提假设，执行器才定结果**：无执行验证证据不得 `confirmed`。
- **防死循环**：`retry_cap=3`、`analysis_attempts` 上限；且**必须为 LLM 调用设全局超时 + 失败后走 fallback（内置字典）**，避免网络卡死拖垮整体。
- **Strict JSON**：只允许合法 JSON，关闭自由文本解释；用 `jsonschema` 校验输出结构，非法即重试或丢弃。

## 6. 关键算法与验收
- 并发调度：`Semaphore + asyncio.gather(return_exceptions=True)`，单点超时/异常只降级该目标（验收：50 目标含 3 超时，整体完成且坏目标记录）。
- 上下文压缩：raw HTTP 响应 → `TargetContext`，目标 token 压缩≥98%（验收：以 tokenizer 实测）。
- 文件哈希监控：基线 `(size,mtime,sha256)` 轮询，仅把变化段喂 LLM。
- 存储：`aiosqlite` 需在 main 里显式 `await store.connect()`；单写入者即可，读并发低。

## 7. 报表 / 交付
- 先做**可运行的最低闭环**，再做防御端，最后补测试与抗幻觉校验。
- 量化指标（吞吐 1000+/min、压缩率 98%、2KB 上下文）为**设计目标**，实现阶段实测后替换为真实值写简历。

## 8. 边界
- 仅用于**授权学习/竞赛环境**，目标以 `settings.yaml` 中 `scope: scoped` 声明为界。
- 不引入方案外依赖；模块间只经 `models.py` 类型流转，不写隐式全局状态。
