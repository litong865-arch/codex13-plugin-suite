# Security Release Review V4 for Claude-like Agents

Use V4 for launch readiness:

```bash
python scripts/security_audit.py --project . --config security-policy.yaml --mode all --out security-review
```

Review `RELEASE_GO_NO_GO.md` and `EVIDENCE_MATRIX.md` before answering.

Run retest after code changes:

```bash
python scripts/security_audit.py --project . --mode retest --previous security-review/security-review.json --out security-review-retest
```

No public launch if hard NO GO remains.
