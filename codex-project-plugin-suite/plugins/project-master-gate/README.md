# 项目总控闸门

内部 ID：project-master-gate

## 用途

统一调度项目开发前、中、后所有闸门插件。

把项目从想法到开发、验收、上线拆成固定流程：先压力测试，再产品可行性，再 Spec，再 API 审查，再工程脚手架，再执行验收，再上线发布，再生成小白执行手册。

## 什么时候使用

当你需要处理与“项目总控闸门”相关的项目工作时，在 Codex 对话里直接说：

使用 project-master-gate 帮我……

## 目录结构

project-master-gate/
├─ .codex-plugin/plugin.json
├─ skills/project-master-gate/SKILL.md
├─ references/checklist.md
├─ references/template.md
└─ references/validation-test-cases.md

## 小白使用方式

1. 在 Codex 的 /plugins 里找到并启用这个插件。
2. 新开一个会话。
3. 复制默认提示词之一，让 Codex 按这个插件的规则输出。
4. 如果输出不够具体，继续要求“给我可复制的下一步命令”。

## 默认提示词

- 使用 project-master-gate 帮我总控这个项目，先不要写代码。
- 按项目总控流程检查这个想法应该先用哪些插件。
- 帮我从决策、可行性、Spec、API、验收、上线到小白教程完整规划这个项目。

<!-- project-master-gate-v1-1-readme -->

## 1.1 扩展能力

项目总控闸门现在不仅能调度项目流程插件，也会判断是否需要调用 Browser、Chrome、Computer Use 和子线程工具。

边界说明：插件本身不能授予工具权限；只有当前 Codex 会话已经启用这些工具时，总控才能建议或调用它们。

推荐提示词：

使用 project-master-gate 帮我总控这个项目。如果需要浏览器、Chrome、Computer Use 或子线程，请自动给出调用计划；如果当前工具不可用，请明确告诉我缺什么。
