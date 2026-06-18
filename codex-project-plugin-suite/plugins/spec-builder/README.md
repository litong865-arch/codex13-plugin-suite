# Spec 生成器

内部 ID：spec-builder

## 用途

把模糊想法变成 Codex 可执行开发规格。

生成 docs/spec.md、docs/acceptance.md、docs/architecture.md、docs/api.md、docs/progress.md，防止 Codex 从模糊想法直接乱写代码。

## 什么时候使用

当你需要处理与“Spec 生成器”相关的项目工作时，在 Codex 对话里直接说：

使用 spec-builder 帮我……

## 目录结构

spec-builder/
├─ .codex-plugin/plugin.json
├─ skills/spec-builder/SKILL.md
├─ references/checklist.md
├─ references/template.md
└─ references/validation-test-cases.md

## 小白使用方式

1. 在 Codex 的 /plugins 里找到并启用这个插件。
2. 新开一个会话。
3. 复制默认提示词之一，让 Codex 按这个插件的规则输出。
4. 如果输出不够具体，继续要求“给我可复制的下一步命令”。

## 默认提示词

- 使用 spec-builder 帮我把这个想法整理成开发 Spec。
- 帮我生成 docs/spec.md、验收标准和开发任务。
- 我只有一个 PRD，请先转成 Codex 可执行 Spec。