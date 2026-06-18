# 小白执行手册生成器

内部 ID：beginner-runbook-builder

## 用途

把复杂技术步骤变成小白能照做的教程。

生成运行、测试、部署、演示、排错、下一步操作的详细小白手册。

## 什么时候使用

当你需要处理与“小白执行手册生成器”相关的项目工作时，在 Codex 对话里直接说：

使用 beginner-runbook-builder 帮我……

## 目录结构

beginner-runbook-builder/
├─ .codex-plugin/plugin.json
├─ skills/beginner-runbook-builder/SKILL.md
├─ references/checklist.md
├─ references/template.md
└─ references/validation-test-cases.md

## 小白使用方式

1. 在 Codex 的 /plugins 里找到并启用这个插件。
2. 新开一个会话。
3. 复制默认提示词之一，让 Codex 按这个插件的规则输出。
4. 如果输出不够具体，继续要求“给我可复制的下一步命令”。

## 默认提示词

- 使用 beginner-runbook-builder 给我生成小白执行手册。
- 把这个项目的运行和部署步骤写成小白教程。
- 告诉我一步一步该点哪里、复制什么、运行什么。