# 小白指挥 Codex 说明

## 最重要的一句话

不要一上来让 Codex 写代码。先让 `project-master-gate` 做总控。

推荐开场：

```text
先不要写代码，请使用 project-master-gate 帮我总控这个项目。
```

## 标准工作流

推荐顺序：

1. `project-master-gate`：先总控，决定插件顺序。
2. `decision-stress-test-gate`：判断值不值得做。
3. `product-feasibility-gate`：判断 MVP 怎么跑通。
4. `spec-builder`：生成开发 Spec。
5. `api-platform-gate`：检查 API 和平台风险。
6. `ai-cost-estimator`：估算 AI/API 成本。
7. `code-drift-inspector`：检查代码漂移。
8. `codex-acceptance-reviewer`：验收 Codex 是否真完成。
9. `release-guardian`：上线发布前检查。
10. `security-release-review`：上线前安全审查。
11. `beginner-runbook-builder`：生成小白执行手册。

辅助插件：

- `user-interview-generator`：找真人验证需求。
- `competitor-analyzer`：分析竞品和替代方案。

## 总控测试提示词

```text
先不要写代码，请使用 project-master-gate 帮我总控：

我想做一个餐饮商家 AI 评论回复 Agent，可以读取美团、抖音、小红书评论，自动生成回复建议，后续可能半自动发布。

请输出项目总控闸门报告，并告诉我：
1. 当前项目处于什么阶段
2. 应该先调用哪些插件
3. 每个插件的调用顺序
4. 每一步我应该复制什么提示词给 Codex
5. 哪些地方会阻塞
6. 下一步最小行动是什么
```

## 常用提示词模板

### 1. 压力测试

```text
使用 decision-stress-test-gate 帮我压力测试这个想法。
先不要鼓励我，请直接找出这个项目最可能失败的原因、最致命假设和 7 天验证计划。
```

### 2. 产品可行性

```text
使用 product-feasibility-gate 检查这个项目。
请判断 MVP 主线怎么跑通、第一版不做什么、API/Mock 怎么处理、开工前还缺什么。
```

### 3. 生成 Spec

```text
使用 spec-builder 帮我把这个想法整理成 docs/spec.md、验收标准、API/Mock 方案、数据结构和 Codex 开发任务。
```

### 4. API / 平台审查

```text
使用 api-platform-gate 帮我检查这个平台功能能不能做。
请判断是否有官方 API、是否需要企业权限、是否有封号风险，以及是否需要 Mock 或半自动方案。
```

### 5. AI 成本估算

```text
使用 ai-cost-estimator 帮我估算这个 AI 产品成本。
请拆出每一步 AI/API 调用，给出单次任务成本公式、100 用户和 1000 用户成本估算。
```

### 6. 代码漂移检查

```text
使用 code-drift-inspector 检查这个项目。
重点看目录是否混乱、Mock 和真实 API 是否混在一起、是否有超大文件、重复代码和架构边界问题。
```

### 7. Codex 验收

```text
使用 codex-acceptance-reviewer 帮我验收 Codex 刚完成的实现。
重点检查主线是否跑通、按钮是否假完成、数据是否保存、刷新后是否保留、Mock 是否标记、测试是否通过。
```

### 8. 上线发布

```text
使用 release-guardian 帮我做上线前检查。
请检查环境变量、API Key、构建、测试、README、版本号、回滚方案和上线后观察项。
```

### 9. 安全审查

```text
使用 security-release-review 帮我做上线前安全审查。
重点检查密钥、权限、隐私、攻击路径、越权风险、日志和发布阻断项。
```

### 10. 小白手册

```text
使用 beginner-runbook-builder 帮我把这个项目的运行、测试、部署、演示和排错步骤写成小白执行手册。
```

### 11. 用户访谈

```text
使用 user-interview-generator 帮我设计用户访谈。
请生成目标用户画像、访谈问题、私信话术、问卷和 7 天验证计划。
```

### 12. 竞品分析

```text
使用 competitor-analyzer 帮我分析竞品。
请列出直接竞品、间接竞品、免费替代方案、切换成本、差异化和最危险竞品。
```

## 判断你有没有指挥对

如果 Codex 的回答包含这些内容，说明你指挥方向是对的：

- 它先分析阶段，而不是直接写代码。
- 它给出插件调用顺序。
- 它指出阻塞风险。
- 它给出下一步可复制提示词。
- 它明确告诉你下一步最小行动。

如果它直接开始写代码，你可以打断它：

```text
停一下。先不要写代码。请回到 project-master-gate 的总控流程，先输出项目总控闸门报告。
```


## Browser、Chrome、Computer Use 和子线程怎么用

这些不是 project-master-gate 自己凭空拥有的权限，而是当前 Codex 会话已经启用相关工具时，总控插件可以判断什么时候该调用它们。

### 什么时候用 Browser

- 检查本地网页、localhost、file:// 页面。
- 点击按钮、填写表单、截图确认 UI。
- 验证前端主流程是否真的跑通。

提示词：

```text
如果需要，请使用 Browser 打开本地页面，检查主流程按钮、页面报错、响应式布局，并截图验证。
```

### 什么时候用 Chrome

- 需要真实登录态、Cookie、已有 Chrome 标签页。
- 需要访问远程平台后台。
- 需要依赖 Chrome 扩展或用户浏览器配置。

提示词：

```text
如果需要登录态，请使用 Chrome 检查页面。只做读取、截图和风险判断，不要提交敏感操作。
```

### 什么时候用 Computer Use

- 需要操作 Windows 桌面软件。
- 需要处理安装器、弹窗、文件管理器、非浏览器 UI。

提示词：

```text
如果需要桌面操作，请使用 Computer Use 检查当前流程，记录每一步看到什么，不要执行不可逆操作。
```

### 什么时候自动拆子线程

适合并行拆分的任务：

- API / 平台审查
- 竞品分析
- Spec 草案
- 代码漂移巡检
- 上线检查
- 小白手册整理

总控提示词：

```text
使用 project-master-gate 总控这个项目。如果当前环境支持子线程，请自动拆分最多 3 个子线程并行处理；每个子线程必须有明确任务、输入、输出格式和停止条件。完成后请汇总所有线程结论。
```

安全边界：

- 不要把密钥、账号密码、隐私数据发给子线程。
- 默认最多 3 个子线程，复杂项目最多 5 个。
- 子线程完成后必须回到总控线程汇总。
- 如果线程工具不可用，总控只能给出拆分建议，不能假装已经创建。
