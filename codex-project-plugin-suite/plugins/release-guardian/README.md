# 上线发布守护器

内部 ID：release-guardian

## 用途

上线前检查构建、密钥、测试、回滚和观察项。

轻量发布闸门：检查 .env、API Key、构建、测试、版本号、README、回滚方案、上线后 24 小时观察清单。

## 什么时候使用

当你需要处理与“上线发布守护器”相关的项目工作时，在 Codex 对话里直接说：

使用 release-guardian 帮我……

## 目录结构

release-guardian/
├─ .codex-plugin/plugin.json
├─ skills/release-guardian/SKILL.md
├─ references/checklist.md
├─ references/template.md
└─ references/validation-test-cases.md

## 小白使用方式

1. 在 Codex 的 /plugins 里找到并启用这个插件。
2. 新开一个会话。
3. 复制默认提示词之一，让 Codex 按这个插件的规则输出。
4. 如果输出不够具体，继续要求“给我可复制的下一步命令”。

## 默认提示词

- 使用 release-guardian 帮我做上线前检查。
- 检查这个项目能不能发布。
- 帮我生成上线发布清单和回滚方案。