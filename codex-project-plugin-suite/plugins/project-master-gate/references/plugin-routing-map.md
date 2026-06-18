# 插件路由图

## 当前检测结果

- decision-stress-test-gate：已检测到
- product-feasibility-gate：已检测到
- 安全闸门指定别名：指定安全闸门别名未检测到，可后续安装
- 安全相关补充检测：另外检测到安全相关 marketplace 插件：security-release-review。已保留，不覆盖。

## 先判断值不值得做

插件：decision-stress-test-gate

触发场景：

- 创业
- 副业
- AI Agent
- 商业化产品
- SaaS
- 自动化工具
- 自媒体账号
- 投资或重大决策

## 再判断怎么做

插件：product-feasibility-gate

触发场景：

- APP
- 小程序
- SaaS
- AI Agent
- Web 工具
- 自动化系统
- Codex 插件

## 生成开发规格

插件：spec-builder

触发场景：

- 只有模糊想法
- 只有 PRD
- 没有 Spec
- 需要 docs/spec.md
- 需要验收标准

## 检查 API / 平台

插件：api-platform-gate

触发场景：

- 第三方平台
- 自动登录
- 自动回复
- 自动发布
- 账号授权
- 支付
- 地图
- 评论
- 图片 / 语音 / 视频 API

## 估算 AI / API 成本

插件：ai-cost-estimator

触发场景：

- AI Agent
- 大模型调用
- 图片 / 语音 / 视频生成
- 批量任务
- 第三方 API 按量计费

## 检查代码漂移

插件：code-drift-inspector

触发场景：

- Codex 改了很多轮
- 代码越来越乱
- 文件越来越大
- mock 和真实逻辑混在一起
- 架构边界不清楚

## 验收 Codex 结果

插件：codex-acceptance-reviewer

触发场景：

- Codex 说完成了
- 要检查主线是否跑通
- 要检查假按钮 / 假数据
- 要检查 README / progress

## 上线发布

插件：release-guardian

触发场景：

- 准备部署
- 准备交付
- 准备演示
- 准备发布到线上

如果检测到安全闸门，继续调用安全闸门做更深安全审查。

## 小白手册

插件：beginner-runbook-builder

触发场景：

- 用户不知道怎么运行
- 用户不知道怎么部署
- 用户需要一步一步教程

## 辅助验证

插件：user-interview-generator、competitor-analyzer

触发场景：

- 需要真人验证需求
- 需要分析竞品和替代方案

<!-- tool-thread-routing-map-v1 -->

## 工具与线程路由

### Browser

用于本地 Web 页面、localhost、页面点击、截图、响应式检查和前端主流程验证。

### Chrome

用于需要真实登录态、Cookie、远程平台、已有 Chrome 标签页或浏览器扩展的场景。

### Computer Use

用于 Windows 桌面应用、文件管理器、安装器、弹窗和非浏览器 UI。

### 子线程

当线程工具可用且用户允许自动拆分时，可创建背景线程分别处理 API 审查、竞品分析、Spec 生成、代码巡检、上线检查和小白手册。
