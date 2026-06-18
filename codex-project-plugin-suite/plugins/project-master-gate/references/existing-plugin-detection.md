# 旧插件检测规则

检查以下目录：

- ~/.codex/plugins/decision-stress-test-gate/
- ~/.codex/plugins/product-feasibility-gate/
- ~/.codex/plugins/security-gate/
- ~/.codex/plugins/safety-gate/
- ~/.codex/plugins/launch-security-gate/
- ~/.codex/plugins/security-release-gate/
- ~/.codex/plugins/safe-launch-gate/

检查 marketplace：

- ~/.agents/plugins/marketplace.json

如果存在，就在报告里标记“已检测到”。

如果不存在，就标记“未检测到，可后续安装”。

## 本次实际检测结果

- decision-stress-test-gate：已检测到
- product-feasibility-gate：已检测到
- 安全闸门指定别名：指定安全闸门别名未检测到，可后续安装
- 安全相关补充检测：另外检测到安全相关 marketplace 插件：security-release-review。已保留，不覆盖。

本次不会创建、覆盖或删除这些旧插件。