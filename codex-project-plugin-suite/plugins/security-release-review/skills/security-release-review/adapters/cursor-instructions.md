# Cursor Instruction: Security Release Review V4

Run:

```bash
python scripts/security_audit.py --project . --config security-policy.yaml --mode all --out security-review
```

GO requires evidence in `EVIDENCE_MATRIX.md`. After fixes, run retest. Do not rely on frontend hiding, prompts, or assumptions as security controls.
