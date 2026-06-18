# AGENTS.md Example: Security Release Review V4

Run V4 before public launch:

```bash
python .agents/skills/security-release-review/scripts/security_audit.py --project . --config security-policy.yaml --mode all --out security-review
```

If app is running:

```bash
python .agents/skills/security-release-review/scripts/security_audit.py --project . --mode dynamic --base-url http://localhost:3000 --out security-review
```

After fixes:

```bash
python .agents/skills/security-release-review/scripts/security_audit.py --project . --mode retest --previous security-review/security-review.json --out security-review-retest
```

Required evidence:

- `EVIDENCE_MATRIX.md`
- `API_ABUSE_TESTS.md`
- `DYNAMIC_SECURITY_TEST.md`
- `SECURITY_RETEST_REPORT.md`
- `RELEASE_GO_NO_GO.md`

Do not approve GO without evidence.
