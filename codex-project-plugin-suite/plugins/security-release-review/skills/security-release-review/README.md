# security-release-review V10

这是一个给 Codex 和其他代码智能体用的商业级上线安全闸门。

V10 的核心变化：在 V5 的安全闸门基础上，逐步加入 V6-V10 能力：语义审查、权限矩阵、补丁草案、攻击路径、上线后守护、运行时日志分析、安全数字孪生、PR 语义审查、审批/SLA、组织控制面、发布契约和成熟度评分。

## 适合什么项目

- Web、API、SaaS、小程序后端。
- 有登录、短信、邮件、支付、Webhook、上传、评论、UGC、后台、AI 聊天或 Agent 工具的项目。
- 餐饮商家系统，尤其是自动回复、评论审核、平台连接器和套餐权限。

## 运行

```bash
python scripts/security_audit.py --project . --mode all --out security-review
```

建议复制并调整安全闸门基线：

```bash
cp assets/security-gate.example.yaml security-gate.yaml
python scripts/security_audit.py --project . --config security-gate.yaml --mode all --out security-review
```

如果应用已启动：

```bash
python scripts/security_audit.py --project . --mode dynamic --base-url http://localhost:3000 --out security-review
```

修复后：

```bash
python scripts/security_audit.py --project . --mode retest --previous security-review/security-review.json --out security-review-retest
```

## 先看哪些报告

1. `RELEASE_GO_NO_GO.md`
2. `SECURITY_RELEASE_REVIEW.md`
3. `EVIDENCE_MATRIX.md`
4. `SECURITY_FIX_PLAN.md`
5. `API_SECURITY_MAP.md`
6. `API_ABUSE_TESTS.md`
7. `SEMANTIC_SECURITY_REVIEW.md`
8. `PERMISSION_MATRIX_TESTS.md`
9. `ATTACK_PATH_GRAPH.md`
10. `PATCH_STRATEGY.md`
11. `AUTO_PATCH_DRAFTS.md`
12. `POST_LAUNCH_GUARD.md`
13. `RUNTIME_LOG_ANALYSIS.md`
14. `SECURITY_DIGITAL_TWIN.md`
15. `PR_SEMANTIC_REVIEW.md`
16. `RELEASE_APPROVAL_WORKFLOW.md`
17. `ORG_SECURITY_CONTROL_PLANE.md`
18. `RELEASE_CONTRACT.md`
19. `SECURITY_MATURITY_SCORE.md`

CI 可读取：

- `security-review.sarif`
- `junit-security.xml`
- `security-abuse-tests.mjs`

## 不能上线的典型情况

- 密钥/token/private key 泄露。
- 管理员接口无后端鉴权或角色校验。
- 用户数据可越权访问。
- 短信、AI、上传、第三方付费 API 无预算和限流。
- AI key 或系统提示词在前端。
- 文件上传无限制且公开访问。
- 支付/Webhook 无签名校验。
- 生产 debug 开启。
- 日志暴露密码、验证码、token、手机号、邮箱等。

## 自测

```bash
python scripts/validate_skill.py .
python scripts/security_audit.py --self-test
python scripts/security_audit.py --project . --mode all --out security-review-test
```
