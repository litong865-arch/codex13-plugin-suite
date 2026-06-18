# V4 Quick Checklist

- [ ] Copy `assets/security-policy.example.yaml` to project root as `security-policy.yaml`.
- [ ] Run `python scripts/security_audit.py --project . --config security-policy.yaml --mode all --out security-review`.
- [ ] If app runs, add `--base-url http://localhost:3000` or run `--mode dynamic`.
- [ ] Open `RELEASE_GO_NO_GO.md` first.
- [ ] Confirm `EVIDENCE_MATRIX.md` has static and dynamic/API evidence.
- [ ] Review `SECURITY_FIX_PLAN.md`.
- [ ] Review `API_SECURITY_MAP.md` and `API_ABUSE_TESTS.md`.
- [ ] Review `AI_RED_TEAM_TESTS.md` if AI exists.
- [ ] Review `CLOUD_RUNTIME_CONFIG_REVIEW.md` and exported cloud config.
- [ ] Review `SUPPLY_CHAIN_REVIEW.md` and CI audit outputs.
- [ ] Review `RESTAURANT_COMPLIANCE_REVIEW.md` for餐饮自动回复/审核/平台授权.
- [ ] After fixes, run retest and keep `SECURITY_RETEST_REPORT.md`.

Immediate NO GO:

- Secret leak.
- Admin API without backend auth/role checks.
- IDOR/BOLA.
- Unlimited SMS/AI/upload costs.
- Frontend AI key or system prompt.
- Unlimited public upload.
- Unsigned payment/webhook.
- Production debug.
- Sensitive logs.
