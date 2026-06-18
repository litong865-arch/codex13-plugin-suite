# Release Gate Rules

## Score

满分 100：

- Critical 每个扣 30 分。
- High 每个扣 15 分。
- Medium 每个扣 5 分。
- Low 每个扣 1 分。

## Decision

- `GO`: 90 分以上，无 Critical，无 High，无 blocks_release。
- `CONDITIONAL GO`: 无 blocks_release，允许内部测试或小范围公开测试。
- `NO GO`: 有 blocks_release、Critical，或分数低于 60。

## Hard NO GO

任一项成立直接 NO GO：

- API key / private key 泄露。
- 管理员接口无鉴权。
- 用户数据可被越权访问。
- 短信接口无限制。
- AI key 在前端。
- AI 接口无限调用。
- 文件上传无限制并公开访问。
- 支付 / Webhook 无签名校验。
- 数据库危险操作无权限控制。
- 生产 debug 开启。
- 日志暴露密码、验证码、token。
