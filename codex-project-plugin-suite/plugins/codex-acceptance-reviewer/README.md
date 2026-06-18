# Codex 执行验收器

内部 ID：codex-acceptance-reviewer

## 用途

检查 Codex 是否真的完成，而不是假完成。

专门验收 Codex 的开发成果：主线是否跑通、按钮是否真可用、数据是否保存、mock 是否标记、API 失败是否有提示、测试是否通过。

## 什么时候使用

当你需要处理与“Codex 执行验收器”相关的项目工作时，在 Codex 对话里直接说：

使用 codex-acceptance-reviewer 帮我……

## 目录结构

codex-acceptance-reviewer/
├─ .codex-plugin/plugin.json
├─ skills/codex-acceptance-reviewer/SKILL.md
├─ references/checklist.md
├─ references/template.md
└─ references/validation-test-cases.md

## 小白使用方式

1. 在 Codex 的 /plugins 里找到并启用这个插件。
2. 新开一个会话。
3. 复制默认提示词之一，让 Codex 按这个插件的规则输出。
4. 如果输出不够具体，继续要求“给我可复制的下一步命令”。

## 默认提示词

- 使用 codex-acceptance-reviewer 帮我验收 Codex 的实现。
- 检查这个项目是不是假完成。
- 帮我确认主线是否真的跑通。