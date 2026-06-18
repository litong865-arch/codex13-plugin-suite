# AI 成本估算器

内部 ID：ai-cost-estimator

## 用途

估算 AI/API 调用成本、速度和额度风险。

检查一次完整流程调用多少次模型、多少钱、是否需要缓存、限流、降级、重试控制和额度保护。

## 什么时候使用

当你需要处理与“AI 成本估算器”相关的项目工作时，在 Codex 对话里直接说：

使用 ai-cost-estimator 帮我……

## 目录结构

ai-cost-estimator/
├─ .codex-plugin/plugin.json
├─ skills/ai-cost-estimator/SKILL.md
├─ references/checklist.md
├─ references/template.md
└─ references/validation-test-cases.md

## 小白使用方式

1. 在 Codex 的 /plugins 里找到并启用这个插件。
2. 新开一个会话。
3. 复制默认提示词之一，让 Codex 按这个插件的规则输出。
4. 如果输出不够具体，继续要求“给我可复制的下一步命令”。

## 默认提示词

- 使用 ai-cost-estimator 帮我估算这个 AI 产品成本。
- 帮我算一次完整流程大概要调用几次模型。
- 检查这个 Agent 成本会不会失控。