# API / 平台可行性审查器

内部 ID：api-platform-gate

## 用途

先查平台是否允许，再决定能不能做。

检查第三方平台 API、自动化权限、企业认证、封号风险、自动登录风险、mock 替代方案和半自动方案。

## 什么时候使用

当你需要处理与“API / 平台可行性审查器”相关的项目工作时，在 Codex 对话里直接说：

使用 api-platform-gate 帮我……

## 目录结构

api-platform-gate/
├─ .codex-plugin/plugin.json
├─ skills/api-platform-gate/SKILL.md
├─ references/checklist.md
├─ references/template.md
└─ references/validation-test-cases.md

## 小白使用方式

1. 在 Codex 的 /plugins 里找到并启用这个插件。
2. 新开一个会话。
3. 复制默认提示词之一，让 Codex 按这个插件的规则输出。
4. 如果输出不够具体，继续要求“给我可复制的下一步命令”。

## 默认提示词

- 使用 api-platform-gate 帮我检查这个平台功能能不能做。
- 检查这个项目是否有真实 API，可以自动化吗？
- 帮我判断这个自动回复/自动发布功能有没有平台风险。