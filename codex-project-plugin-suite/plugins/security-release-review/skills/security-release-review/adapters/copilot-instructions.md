# Copilot Instruction: Security Release Review V4

Run:

```bash
python scripts/security_audit.py --project . --config security-policy.yaml --mode all --out security-review
```

Use `security-review.sarif` and `junit-security.xml` for CI. Use `RELEASE_GO_NO_GO.md` for the launch decision. Retest after fixes.
