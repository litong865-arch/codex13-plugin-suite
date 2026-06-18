# Evidence-Based Gate Guide

V4 的 GO/NO GO 必须基于证据。

证据类型：

- Static: 文件路径、行号、规则命中。
- Dynamic: HTTP 状态码、响应头、未登录/admin/敏感路径访问结果。
- API abuse: 多角色、IDOR、限流、上传、Webhook 测试。
- Retest: fixed/unresolved/new 差异。
- Manual: 云平台、数据库、供应商后台截图或导出配置。

规则：

- 没有动态/API 证据，最多 `CONDITIONAL GO`。
- `critical/high` 不能靠口头解释关闭。
- 每个上线批准必须保留 `EVIDENCE_MATRIX.md`。
