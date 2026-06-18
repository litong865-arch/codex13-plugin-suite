# V3 Security Checklist

## Secrets

- [ ] API key、token、private key、数据库密码不在仓库、日志、CI 输出或前端 bundle。
- [ ] `.env` 不入库，`.env.example` 只有占位符。
- [ ] GitHub Actions / CI 使用 secrets store，不硬编码凭证。

## Auth

- [ ] 登录、注册、重置密码、验证码接口需要限速和防枚举。
- [ ] session/JWT secret 足够强。
- [ ] token 有过期时间、撤销机制和安全 cookie 配置。
- [ ] remember-me 有设备绑定、过期和撤销。

## Authorization

- [ ] 游客、普通用户、会员、管理员、超级管理员权限边界明确。
- [ ] 管理员接口有后端鉴权和角色校验。
- [ ] 所有 ID 访问都有 owner/tenant/merchant/object-level authorization。
- [ ] 前端隐藏按钮不作为权限控制。

## SMS / Email OTP

- [ ] IP、手机号、账号、设备、会话维度限速。
- [ ] 单用户每日限制、失败次数限制、冷却时间。
- [ ] 预算上限、异常报警、供应商账单告警。
- [ ] OTP 使用安全随机数、短期有效期、防重放。

## UGC

- [ ] 昵称、头像、简介、评论、留言、帖子、弹幕、AI 生成内容有审核策略。
- [ ] 举报、删除、下架、封号、禁言、审核队列、管理员日志齐全。
- [ ] UGC 渲染转义或严格白名单清洗。

## Upload

- [ ] 服务端限制文件大小、数量、图片尺寸和请求体。
- [ ] MIME、扩展名、magic bytes 校验。
- [ ] 文件名清洗、防路径穿越。
- [ ] 私有桶、签名 URL、过期时间、防公共图床。
- [ ] 删除、下架、隔离、恶意文件处理能力。

## AI / Agent

- [ ] AI key、系统提示词、内部规则只在服务端。
- [ ] prompt injection、系统提示词泄露、API key 泄露、越权工具调用测试。
- [ ] 输入审核、输出审核、敏感输出过滤。
- [ ] token 成本控制、模型滥用报警、kill switch。
- [ ] 工具调用有白名单、最小权限、沙箱、审计日志和人工确认。

## Config / Logs / Incident

- [ ] CORS 不过宽。
- [ ] 生产 debug 关闭。
- [ ] source map 不公开。
- [ ] 安全响应头齐全。
- [ ] 日志不含密码、token、验证码、手机号、邮箱、身份证。
- [ ] 可一键关闭注册、上传、评论、AI、短信。
- [ ] 有维护模式、回滚方案、异常报警。
