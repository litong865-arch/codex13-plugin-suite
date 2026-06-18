# Security Release Review V3 Agent Rules

Run the V3 gate before public launch:

```bash
python scripts/security_audit.py --project . --mode all --out security-review
```

Do not claim the project is safe without evidence. Required evidence includes:

- Static scan findings.
- Threat model.
- API security map and API abuse tests.
- Agent tool permission review.
- Cost abuse review.
- Dynamic test report or documented reason dynamic tests could not run.
- Fix plan.
- Retest report after fixes.
- Final `RELEASE_GO_NO_GO.md`.

The final answer must say one of:

- `GO`
- `CONDITIONAL GO`
- `NO GO`
