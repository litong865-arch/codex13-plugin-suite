# 代码漂移巡检器

内部 ID：code-drift-inspector

## 用途

防止 Codex 把项目越写越乱。

检查目录、分层、命名、依赖、mock、API、超大文件、重复代码、废弃文件、测试缺口和技术债。

## 什么时候使用

当你需要处理与“代码漂移巡检器”相关的项目工作时，在 Codex 对话里直接说：

使用 code-drift-inspector 帮我……

## 目录结构

code-drift-inspector/
├─ .codex-plugin/plugin.json
├─ skills/code-drift-inspector/SKILL.md
├─ references/checklist.md
├─ references/template.md
└─ references/validation-test-cases.md

## 小白使用方式

1. 在 Codex 的 /plugins 里找到并启用这个插件。
2. 新开一个会话。
3. 复制默认提示词之一，让 Codex 按这个插件的规则输出。
4. 如果输出不够具体，继续要求“给我可复制的下一步命令”。

## 默认提示词

- 使用 code-drift-inspector 检查我的项目有没有代码漂移。
- 帮我检查 Codex 多轮修改后代码是否变乱。
- 检查这个项目的架构边界、mock 和真实 API 是否混乱。