# API Abuse Test Guide

必须测试：

- 未登录访问受保护接口。
- 普通用户访问管理员接口。
- 用户 A 访问用户 B 的资源。
- 修改 URL、query、body 中的 ID 做 IDOR/BOLA。
- 重复请求测试限流。
- 大 payload 测试请求体限制。
- 文件上传绕过：MIME、扩展名、magic bytes、大小、公开 URL。
- AI 接口刷 token。
- 短信接口刷费用。
- Webhook 伪造、篡改、重放。

测试应优先在本地、mock 或 staging 执行。生产环境成本型或破坏性测试必须先获得明确授权。
