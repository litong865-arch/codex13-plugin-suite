# 插件验证测试用例

## 测试用例 1

输入：
我想做一个餐饮商家 AI 评论回复 Agent，先不要写代码。

期望输出：
- 先建议 decision-stress-test-gate 和 product-feasibility-gate。
- 涉及美团、抖音、小红书时提示必须使用 api-platform-gate。
- 给出每个阶段的调用提示词。

## 测试用例 2

输入：
Codex 已经做完了一个 SaaS，我准备上线。

期望输出：
- 建议使用 code-drift-inspector、codex-acceptance-reviewer、release-guardian。
- 如果检测到安全闸门，提示继续做安全审查。
- 输出小白下一步行动。