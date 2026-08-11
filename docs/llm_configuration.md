# 配置安全分析 LLM

平台的 Live Agent 使用 Chat Completions-compatible HTTP 协议，调用方式是服务器向 `<base_url>/chat/completions` 发送 Bearer API Key、模型名和 messages。因此可接入 OpenAI、Qwen/DashScope、vLLM、LiteLLM 或企业内部的兼容网关。

## Mock 模式

默认 Demo 使用 Mock 模式，完全不需要 LLM。Agent 调查按钮会返回固定的攻击链、处置优先级和 `event_uid` 证据引用，适合没有网络、数据库或模型密钥的客户现场。

## Live 模式

通过 Secret 或环境变量配置。API Key 只能保存在服务端环境，不应提交到 `.env`、镜像或浏览器代码。

```bash
LLM_ENABLED=true
LLM_API_BASE=https://api.openai.com/v1
LLM_API_KEY=replace-with-server-secret
LLM_MODEL=your-approved-model
LLM_TIMEOUT_SECONDS=45
```

Qwen/DashScope 提供 OpenAI-compatible 接口；选择与账户区域相符的官方 Base URL、API Key 和模型名即可。页面中的 Qwen 预设填写中国大陆兼容端点，国际账户应按 Qwen 官方文档替换为对应区域地址。Qwen 官方说明也明确该兼容方式通过 `base_url`、`api_key`、`model` 三项切换。[Qwen OpenAI compatibility](https://docs.qwencloud.com/api-reference/toolkitframework/openai-compatible/overview)

首页“配置 LLM”只进行一次临时连通性测试，不保存 API Key。正式开启实时推理必须配置上述环境变量，并重启服务；查看当前脱敏配置可调用 `GET /v1/system/llm`。

## 使用边界

- Mock 模式永远不发送模型请求。
- Live Agent 只有在请求体设置 `use_llm=true` 且 `LLM_ENABLED=true` 时调用模型。
- 传给模型的上下文包含受限图邻域、告警和事件证据，并要求按 `event_uid` 或 `alert_id` 引用；模型输出是辅助研判，不是攻击成立的唯一依据。
- OpenAI API Key 应通过服务端环境变量或密钥管理器加载，并使用 Bearer 认证；不要暴露到浏览器。[OpenAI API authentication guidance](https://platform.openai.com/docs/api-reference/backward-compatibility?lang=ruby)
