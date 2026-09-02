# AI_INIT — AWD 智能攻防半自动化 Agent 初始指令

> 下游 AI 进入本目录时，粘贴以下【正文块】即可无缝开工。本目录只含规划层文档（无业务代码），由下游 AI 依据 plan 落地实现。

---

【正文块】
你是一个安全竞赛 AWD 项目的实现工程师，进入 `/data/Projects/awd-ai-agent/` 开工，语言 Python 3.11+。

【开工前先读】
1. `agent.md` — 定位 / 技术选型 / 状态机 / AI 约束 / 边界。
2. `IMPLEMENTATION_PLAN.md` — 目录架构 / 数据 Schema / 数据流 / 分阶段路线图 / 简历亮点。

【上下文规则】
- 只在本目录内改动；模块职责见 plan；模块间只经 `awd/models.py` 的 TargetContext / Finding 流转。
- 禁止写死业务逻辑：目标 / 并发 / 超时 / LLM 端点统一从 `config/settings.yaml` 读取。
- 所有 LLM 调用统一走 `awd/llm/client.py`，不直接 import 各厂商 SDK；该模块需区分 OpenAI 兼容（`response_format={"type":"json_object"}`）与 Ollama（`format:"json"`）的 JSON 模式传参。
- 状态机 / 数据 Schema 以 plan 为准，不允许自行增删字段；确需变更先在你实现前给出理由。
- 每次 LLM 调用必须设超时，超时/网络错误走内置字典降级，不得阻塞全局调度。

【关键约束】
- 本工具仅用于授权学习/竞赛环境的攻防演练；仅针对 config 中 `scope: scoped` 声明的目标，越界即拒绝。

【第一阶段启动动作】
1. 铺设 `config/settings.yaml` + `awd/models.py` 的 TargetContext / Finding。
2. 实现 `awd/scheduler.py` 的并发探测池（Semaphore + gather(return_exceptions=True)）。
3. 写 `tests/test_scheduler.py`：50 个假目标、3 个模拟超时，断言整体完成且坏目标被降级记录。
4. 实现 `awd/llm/client.py`：OpenAI/Ollama 双后端 + JSON 模式 + 超时 + 降级。
5. 完成后返回：改了哪些文件、测试命令与通过情况、以及需要我澄清的接口决策点。

【不要做】
- 不要写业务无关扩展、不要重构模块、不要引入方案外库。

【验收指标】见 `IMPLEMENTATION_PLAN.md` 分阶段路线图；量化数据均为设计目标，实现后以实测替换。
