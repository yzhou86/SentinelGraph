# 客户快速 Demo（3–5 分钟）

目标是展示：平台能将不同源的安全日志归一为 OCSF，在 StarRocks 上立刻关联、检测和提供可审计的 Agent 上下文，而不是只做日志搜索。

## Demo 前准备

```bash
docker compose up --build
open http://localhost:8000
```

等待页面出现后，确认 `curl http://localhost:8000/health?mode=mock` 返回 `{"status":"ok","mode":"mock"}`。Mock 模式不连接 StarRocks、向量库或 LLM，所有演示按钮均有确定性返回结果；因此可在客户现场离线展示。Compose 的演示环境已设置 `DEMO_ENABLED=true`，但 Mock 模式本身不依赖该开关。生产环境必须关闭 Demo 入口。

## 推荐讲解顺序

1. 首页默认是 **Mock 模式**。确认右上角显示 `MOCK / NO DEPENDENCIES`，选择一个场景并点击 **启动场景演示**。
2. 先讲左侧的**攻击故事**：每阶段都包含可回溯的 OCSF `event_uid` 与 MITRE 技术，而不是让模型编造故事。
3. 再讲**事件研判**：风险分数、置信度与业务影响来自服务端确定性场景；右侧同时明确展示“尚待验证”，避免把相关性包装为归因结论。
4. 点击 **查看告警**，突出告警的证据 ID、时间窗口、阈值和实体分组。点击 **展开攻击图**，解释入口实体只进行 1–3 跳且大小受限的邻域查询，避免在百亿关系流中全图扫描。
5. 点击 **Agent 调查**，强调 Mock 返回的是固定、可重复讲解的证据结论；它没有调用 LLM。切换到 Live 后，结论材料包含图边、`event_uid` 原始 OCSF 证据和检索到的 playbook。真实 Agent 被要求引用证据，向量相似度不能单独作为入侵结论。
6. 点击 **解析报告为图关系**。Mock 会用当前场景的事件报告提取 IOC 与关系，并在页面展示来源证据、置信度和 `pending_review`。强调“同句共现”只是调查入口；客户现场切到 Live 后，可粘贴真实报告并写入 StarRocks 图边及审核台账。
7. 点击 **历史聚类分析**，切换到“事后分析”视角。Mock 会立刻给出当前故事的确定性历史行为簇、关联实体、跨 OCSF 类别信号和证据事件；Live 则读取最近 7 天的 StarRocks 数据，以前 30 天 class 基线解释排序。强调：这是可解释的调查候选项，不是模型归因或自动处置结论。

## 场景与可讲解的业务风险

| 场景 | 证据链 | 客户价值 |
| --- | --- | --- |
| 互联网凭证攻击 → 异常外联 → 高危暴露 | 5 次失败认证、后续成功登录、连续 TLS 外联、关键 CVE | 演示身份、网络、漏洞三类数据如何在同一资产上下文关联。 |
| 云账号接管 → 权限提升 → 对象存储访问 | 新地理登录、无 MFA、高权限 `AssumeRole`、对象读取和异常转发 | 演示 CloudTrail / 云审计如何支持云身份和数据访问调查。 |
| 终端入侵 → 横向移动 → 勒索影响 | 可疑 PowerShell、凭据转储、SMB、备份删除和批量加密 | 演示主机、网络、文件影响如何压缩为可执行的处置顺序。 |

## 备用 CLI

```bash
sentinelgraph demo --tenant customer-demo
sentinelgraph ingest ./customer-ecs.jsonl --format ecs --tenant customer-demo
sentinelgraph ingest ./cloudtrail.jsonl --format cloudtrail --tenant customer-demo
sentinelgraph detect --tenant customer-demo
```

## 客户常见问题

- **已有 Elastic / CloudTrail / Zeek 怎么接？** 使用 `POST /v1/ingest/{ecs|cloudtrail|zeek|common_json}` 或 CLI `--format`。适配器将常用字段映射为 OCSF，并在 `raw_event` 保存原文。
- **已有 Kafka / 湖仓怎么办？** 使用 `sql/kafka_routine_load.sql` 的入口模板和 `sql/iceberg_catalog.sql` 的冷层模板；生产中建议在 Flink/Connect 完成大规模 OCSF 标准化。
- **LLM 是否直接判定攻击？** 不会。平台提供受限图邻域、可引用事件和语义上下文；处置结论仍需要组织的规则、人工与流程验证。
- **历史数据怎么做复盘或威胁狩猎？** 调用 `POST /v1/retrospective/analyses`，指定时间窗、会话间隔和读取上限。平台仅把时间接近且共享 OCSF 用户、IP、资产、资源、云账户或 trace 的事件放入候选簇，并返回 `event_uid` 以便复核原始证据。
- **客户现场没有数据库或模型 API？** 保持 Mock 模式即可。所有数据、告警、图谱和分析结论都由服务端模拟器返回，不会访问外部网络或本地数据库。
