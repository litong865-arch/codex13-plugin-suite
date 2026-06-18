# 项目标准流程

1. decision-stress-test-gate
2. product-feasibility-gate
3. spec-builder
4. api-platform-gate
5. ai-cost-estimator
6. code-drift-inspector
7. codex-acceptance-reviewer
8. release-guardian
9. beginner-runbook-builder

可选辅助：

- user-interview-generator
- competitor-analyzer

安全补充：

- security-gate
- safety-gate
- launch-security-gate
- security-release-gate
- safe-launch-gate
- security-release-review（仅当本地 marketplace 中存在时作为安全发布审查补充）

<!-- tool-thread-workflow-v1 -->

# 扩展调度能力

项目总控闸门除了调度插件，也要判断是否需要调用：

- Browser：本地 Web 验证、页面点击、截图。
- Chrome：真实登录态、远程平台、已有标签页。
- Computer Use：Windows 桌面应用和非浏览器 UI。
- 子线程：并行拆分 API 审查、竞品分析、Spec、代码巡检、上线检查。

这些能力不是插件自身权限，只有当前 Codex 会话暴露相应工具时才能使用。
