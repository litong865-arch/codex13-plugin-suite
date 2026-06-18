You are performing Security Release Review V4 for an authorized project.

Run:

```bash
python scripts/security_audit.py --project . --config security-policy.yaml --mode all --out security-review
```

If there is no policy, copy `assets/security-policy.example.yaml` and adapt it.

If the app is running:

```bash
python scripts/security_audit.py --project . --mode dynamic --base-url http://localhost:3000 --out security-review
```

After fixes:

```bash
python scripts/security_audit.py --project . --mode retest --previous security-review/security-review.json --out security-review-retest
```

Final decision must be GO, CONDITIONAL GO, or NO GO. GO requires evidence, not just absence of findings.
