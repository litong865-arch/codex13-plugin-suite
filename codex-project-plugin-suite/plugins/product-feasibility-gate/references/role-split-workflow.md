# AI 角色分工工作流

不要让一个聊天框同时承担所有角色。

建议角色：

## 产品 Agent

负责：

- 目标用户
- 痛点
- MVP
- Spec
- 验收标准

## 研发 Agent

负责：

- 根据 Spec 写代码
- 跑测试
- 输出实现说明

## UI Agent

负责：

- 界面风格
- 设计参考
- 页面布局
- 交互细节

## 测试 Agent

负责：

- 根据验收标准测试
- 记录失败
- 输出 test-report.md

## 安全 / 上线 Agent

负责：

- 密钥检查
- 隐私检查
- 日志检查
- 上线风险检查

角色交接靠产物，不靠长聊天记录。

交接产物：

- docs/spec.md
- docs/acceptance.md
- docs/architecture.md
- design/reference.md
- README.md
- progress.md
- test-report.md
