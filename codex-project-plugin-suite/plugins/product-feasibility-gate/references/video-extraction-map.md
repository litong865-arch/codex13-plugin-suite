# 视频内容提取与新增功能映射

## 视频 A：造脚手架：工程师的新角色

提取内容：

1. AI 编程不是只靠提示词，而是靠基础设施。
2. 工程师的新角色是设计脚手架、定义边界、搭建反馈、翻译判断。
3. 项目需要分层架构。
4. 项目需要 AI 可读知识地图。
5. Codex 需要日志、指标、浏览器调试、测试等反馈。
6. 需要自动化静态检查，防止 Code Drift。
7. 需要持续清理和持续重构。

新增到插件的功能：

- AI 工程脚手架检查
- 分层架构与边界检查
- AI 可读知识地图
- 反馈系统检查
- 静态检查与代码漂移检查
- 持续清理与持续重构计划

新增文件：

- references/ai-engineering-scaffold-checklist.md
- references/architecture-boundary-rules.md
- references/ai-knowledge-map-guide.md
- references/feedback-loop-checklist.md
- references/static-checks-and-code-drift.md
- references/continuous-refactor-checklist.md

和原产品可行性内容的区别：

原有功能主要判断产品、MVP、API、Mock、上线轻量风险。
视频 A 新增的是工程执行层，重点是让 Codex 长期稳定开发，防止代码库腐烂。

## 视频 B：Vibe Coding 开工前准备

提取内容：

1. 开工前先整理文档结构。
2. 不要把所有东西放在一个文件夹。
3. 建议区分 docs / app / design。
4. PRD 不等于 Spec。
5. PRD 是产品意图，Spec 是 AI 开发和验收标准。
6. 先定义 MVP，再输出 Spec，再让 AI 开发。
7. 开发前必须初始化 Git。
8. 每个关键节点 commit，出问题可以回滚。
9. 产品、研发、UI、测试角色要分工。
10. 角色之间靠文档产物交接，而不是靠长聊天记录。

新增到插件的功能：

- 开工前目录结构检查
- PRD 与 Spec 区分
- Spec 最低要求
- Git 仓库与回滚点检查
- AI 角色分工检查

新增文件：

- references/preflight-project-setup-checklist.md
- references/spec-vs-prd-guide.md
- references/git-workflow-checklist.md
- references/role-split-workflow.md

和原产品可行性内容的区别：

原有功能已经有 MVP 主线和验收标准。
视频 B 新增的是 Codex 开工前准备：目录、Spec、Git、角色分工，确保 AI 不从模糊想法直接进入混乱开发。

## 本次没有重复新增的内容

以下内容属于产品可行性闸门原本就应该具备的能力，本插件保留但不重复归因到两个视频：

- 目标用户与痛点
- MVP 主线
- 第一版不做清单
- API / Mock 检查
- AI JSON Schema
- 验收标准
- 异常处理
- 日志
- 成本
- 安全隐私
- Launch / Scale 轻量检查
