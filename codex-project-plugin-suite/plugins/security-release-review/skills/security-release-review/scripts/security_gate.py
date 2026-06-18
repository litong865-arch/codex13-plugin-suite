#!/usr/bin/env python3
"""
Release Safety Gate - heuristic release-security scanner.

This script is intentionally dependency-free. It scans a repository for common
launch-readiness risks inspired by the release-safety-gate skill:
SMS/OTP abuse, UGC moderation gaps, upload/public file-host risks, AI prompt
and tool risks, authz gaps, secrets, permissive CORS, debug config, and unsafe
SQL patterns.

It is not a complete SAST/DAST tool. Treat findings as leads to verify.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "blocker": 4,
}

TEXT_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".py", ".rb", ".go", ".java", ".kt", ".kts", ".cs", ".php",
    ".rs", ".swift", ".scala", ".clj", ".ex", ".exs",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".env", ".example",
    ".md", ".txt", ".sql", ".graphql", ".gql",
    ".html", ".css", ".scss", ".vue", ".svelte",
    ".dockerfile", "", ".sh", ".bash", ".zsh",
}

DEFAULT_EXCLUDES = {
    ".git", ".hg", ".svn", ".idea", ".vscode",
    "node_modules", "vendor", "dist", "build", "coverage", ".next", ".nuxt",
    "target", "out", "tmp", "temp", ".cache", ".turbo", ".parcel-cache",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "Pods", "DerivedData", "bin", "obj",
}

GENERATED_REPORT_NAMES = {
    "security_release_review.md",
    "security_findings.json",
    "release_safety_gate_report.md",
    "release_safety_gate_findings.json",
}

PLACEHOLDER_RE = re.compile(
    r"(?i)(example|sample|dummy|placeholder|changeme|change_me|replace|replace_me|"
    r"your[_-]?key|your[_-]?secret|test[_-]?key|fake|mock|xxx|todo|not[_-]?set)"
)


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    file: str
    line: int
    evidence: str
    recommendation: str
    policy: str


def normalize_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace(os.sep, "/")
    except ValueError:
        return str(path).replace(os.sep, "/")


def is_probably_text(path: Path, max_file_size: int) -> bool:
    if not path.is_file():
        return False
    if path.stat().st_size > max_file_size:
        return False
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name in {"dockerfile", "makefile", "procfile", "gemfile", "rakefile"}:
        return True
    if suffix not in TEXT_EXTENSIONS:
        return False
    try:
        with path.open("rb") as f:
            chunk = f.read(2048)
        if b"\0" in chunk:
            return False
        chunk.decode("utf-8", errors="strict")
        return True
    except UnicodeDecodeError:
        # Some repos have latin-1 readmes/configs. Still scan with replacement.
        return True
    except OSError:
        return False


def iter_files(root: Path, max_file_size: int) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDES and not d.startswith(".") or d in {".github"}]
        for filename in files:
            lowered = filename.lower()
            if lowered in GENERATED_REPORT_NAMES or lowered.endswith(".sarif"):
                continue
            path = Path(current) / filename
            if is_probably_text(path, max_file_size=max_file_size):
                yield path


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def clean_evidence(s: str, limit: int = 180) -> str:
    s = " ".join(s.strip().split())
    s = redact_secret_like_values(s)
    if len(s) > limit:
        return s[: limit - 1] + "…"
    return s


def redact_secret_like_values(s: str) -> str:
    # Redact obvious quoted or assignment values while preserving context.
    s = re.sub(r"(sk-[A-Za-z0-9_\-]{6})[A-Za-z0-9_\-]{10,}", r"\1…REDACTED", s)
    s = re.sub(r"(AKIA[0-9A-Z]{4})[0-9A-Z]{12}", r"\1…REDACTED", s)
    s = re.sub(
        r"(?i)((api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"])([^'\"]{8,})(['\"])",
        r"\1…REDACTED\4",
        s,
    )
    return s


def add_finding(
    findings: List[Finding],
    seen: set,
    *,
    severity: str,
    category: str,
    title: str,
    file: str,
    line: int,
    evidence: str,
    recommendation: str,
    policy: str,
) -> None:
    key = (category, title, file, line)
    if key in seen:
        return
    seen.add(key)
    findings.append(
        Finding(
            id=f"RSG-{len(findings) + 1:04d}",
            severity=severity,
            category=category,
            title=title,
            file=file,
            line=line,
            evidence=clean_evidence(evidence),
            recommendation=recommendation,
            policy=policy,
        )
    )


def has_any(text: str, terms: Sequence[str]) -> bool:
    lower = text.lower()
    return any(term.lower() in lower for term in terms)


def find_first_line(text: str, patterns: Sequence[str]) -> Tuple[int, str]:
    for pattern in patterns:
        m = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL)
        if m:
            return line_for_offset(text, m.start()), m.group(0)
    return 1, ""


def is_client_path(rel: str, text: str) -> bool:
    lower = rel.lower()
    if "use client" in text[:1000].lower():
        return True
    client_markers = [
        "/components/", "/pages/", "/public/", "/client/", "/frontend/",
        "/app/", "src/components/", "src/pages/", "src/app/",
    ]
    return any(marker in lower for marker in client_markers) and not any(
        server_marker in lower for server_marker in ["/api/", "/server/", "route.ts", "route.js"]
    )


def scan_secrets(text: str, rel: str, findings: List[Finding], seen: set) -> None:
    patterns = [
        ("OpenAI-style API key literal", r"sk-[A-Za-z0-9_\-]{20,}"),
        ("AWS access key literal", r"AKIA[0-9A-Z]{16}"),
        ("Private key block", r"-----BEGIN (RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----"),
        (
            "Hard-coded secret-like assignment",
            r"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"][^'\"\n]{12,}['\"]",
        ),
    ]
    for title, pattern in patterns:
        for m in re.finditer(pattern, text):
            evidence = m.group(0)
            if PLACEHOLDER_RE.search(evidence):
                continue
            add_finding(
                findings,
                seen,
                severity="blocker",
                category="Secrets",
                title=title,
                file=rel,
                line=line_for_offset(text, m.start()),
                evidence=evidence,
                recommendation="Remove the real secret from the repository/client/logs, rotate it, and load it from a protected server-side secret store.",
                policy="真实密钥、私钥、供应商 token 不得入库、进前端或进日志。",
            )

    # Client-exposed environment variables that look sensitive.
    for m in re.finditer(r"(?i)(NEXT_PUBLIC|VITE|PUBLIC)_?[A-Z0-9_]*(KEY|SECRET|TOKEN)[A-Z0-9_]*", text):
        add_finding(
            findings,
            seen,
            severity="high",
            category="Secrets",
            title="Potentially sensitive client-exposed env variable",
            file=rel,
            line=line_for_offset(text, m.start()),
            evidence=m.group(0),
            recommendation="Verify this value is safe for browsers. Model, SMS, storage, database, and admin secrets must be server-side only.",
            policy="前端公开变量不能包含密钥、内部规则或供应商 token。",
        )


def scan_cors_debug_sql(text: str, rel: str, findings: List[Finding], seen: set) -> None:
    cors_patterns = [
        r"Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*",
        r"origin\s*[:=]\s*['\"]\*['\"]",
        r"cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]\*['\"]",
    ]
    line, evidence = find_first_line(text, cors_patterns)
    if evidence:
        severity = "high" if re.search(r"credentials\s*[:=]\s*true", text, re.IGNORECASE) else "medium"
        add_finding(
            findings,
            seen,
            severity=severity,
            category="API/Auth",
            title="Permissive CORS configuration",
            file=rel,
            line=line,
            evidence=evidence,
            recommendation="Restrict CORS origins to trusted domains. Do not combine wildcard origins with credentials.",
            policy="CORS 必须收敛；凭证请求不能配合通配来源。",
        )

    debug_patterns = [
        r"(?i)debug\s*[:=]\s*true",
        r"(?i)app\.run\([^\)]*debug\s*=\s*true",
        r"(?i)NODE_ENV\s*[:=]\s*['\"]?development",
        r"(?i)APP_DEBUG\s*[:=]\s*['\"]?true",
    ]
    line, evidence = find_first_line(text, debug_patterns)
    if evidence and "test" not in rel.lower():
        add_finding(
            findings,
            seen,
            severity="medium",
            category="Config",
            title="Debug/development mode may be enabled",
            file=rel,
            line=line,
            evidence=evidence,
            recommendation="Ensure production disables debug mode, detailed stack traces, test accounts, and seed/mock behavior.",
            policy="生产环境必须关闭 debug 和详细错误堆栈。",
        )

    sql_patterns = [
        r"(?i)\b(query|execute|raw|exec)\s*\(\s*`[^`]*\$\{[^`]+`",
        r"(?i)\b(query|execute|raw|exec)\s*\(\s*['\"][^'\"]*\+[^\)]*\)",
        r"(?i)SELECT\s+[^\n;]+\+\s*(req\.|request\.|params|body|query)",
    ]
    line, evidence = find_first_line(text, sql_patterns)
    if evidence:
        add_finding(
            findings,
            seen,
            severity="high",
            category="API/Auth",
            title="Possible raw SQL string interpolation",
            file=rel,
            line=line,
            evidence=evidence,
            recommendation="Use parameterized queries/ORM bindings and add tests for malicious input. Verify this is not user-controlled SQL.",
            policy="数据库查询必须参数化，不能拼接用户输入。",
        )


def scan_sms_otp(text: str, rel: str, findings: List[Finding], seen: set) -> None:
    if not has_any(text, ["sms", "otp", "verifycode", "verification", "验证码", "twilio", "sendSms", "send_sms", "sendVerification", "phone"]):
        return
    if not has_any(text, ["twilio", "sms", "otp", "验证码", "verifyCode", "sendSms", "verification"]):
        return

    rate_terms = ["ratelimit", "rate_limit", "throttle", "cooldown", "quota", "bucket", "limit", "redis", "ip", "device", "fingerprint", "daily", "hourly", "budget", "captcha"]
    line, evidence = find_first_line(text, [r"(?i)(sendSms|send_sms|twilio|otp|verifyCode|verification|验证码)[^\n]{0,120}"])
    if not has_any(text, rate_terms):
        add_finding(
            findings,
            seen,
            severity="blocker",
            category="SMS/OTP",
            title="SMS/OTP flow without obvious rate limit or budget controls",
            file=rel,
            line=line,
            evidence=evidence or "SMS/OTP-related code detected",
            recommendation="Add IP/account/phone/device/session rate limits, cooldown, attempt limits, global budget alerts, and provider billing alarms before public launch.",
            policy="短信/邮件/验证码接口不能裸奔，必须有限速、预算和异常报警。",
        )
    elif not has_any(text, ["budget", "billing", "alarm", "alert", "成本", "预算", "告警", "报警"]):
        add_finding(
            findings,
            seen,
            severity="high",
            category="SMS/OTP",
            title="SMS/OTP flow has some limit signals but no obvious budget/alert control",
            file=rel,
            line=line,
            evidence=evidence or "SMS/OTP-related code detected",
            recommendation="Verify provider-level budget caps and abnormal-send alerts exist; add them if missing.",
            policy="成本型接口必须有全局预算、账单阈值和异常峰值报警。",
        )

    if re.search(r"(?i)Math\.random\s*\(\s*\).*?(otp|code|验证码)", text, re.DOTALL) or re.search(
        r"(?i)(otp|code|验证码).*?Math\.random\s*\(", text, re.DOTALL
    ):
        line, evidence = find_first_line(text, [r"(?i).{0,40}Math\.random\s*\(\s*\).{0,80}"])
        add_finding(
            findings,
            seen,
            severity="high",
            category="SMS/OTP",
            title="OTP may use non-cryptographic randomness",
            file=rel,
            line=line,
            evidence=evidence,
            recommendation="Generate OTPs with a cryptographically secure RNG and enforce expiry, replay protection, and attempt limits.",
            policy="验证码必须使用安全随机数并限制重放与尝试次数。",
        )


def scan_uploads(text: str, rel: str, findings: List[Finding], seen: set) -> None:
    upload_indicators = ["upload", "multipart", "multer", "formidable", "busboy", "filepond", "s3", "storage", "blob", "bucket", "oss", "r2", "supabase.storage", "图片", "文件"]
    if not has_any(text, upload_indicators):
        return
    if not has_any(text, ["upload", "multipart", "multer", "formidable", "busboy", "file", "image", "avatar", "s3", "bucket", "storage", "blob", "图片", "文件"]):
        return

    line, evidence = find_first_line(text, [r"(?i)(upload|multipart|multer|formidable|busboy|file|image|avatar|bucket|storage)[^\n]{0,120}"])
    lower = text.lower()

    has_size_limit = has_any(lower, ["limits", "filesize", "file_size", "maxsize", "max_size", "content-length", "size_limit", "limit", "最大", "大小"])
    has_type_check = has_any(lower, ["mimetype", "mime", "content-type", "filetype", "magic", "extension", "extname", "sharp", "imagemagick", "image-size", "类型", "格式"])
    has_moderation = has_any(lower, ["moderation", "review", "approve", "pending", "scan", "virus", "clamav", "nsfw", "审核", "风控", "隔离"])
    has_private_access = has_any(lower, ["signedurl", "signed_url", "presigned", "private", "expires", "acl", "authorization", "token", "签名", "私有", "过期"])

    if not has_size_limit:
        add_finding(
            findings,
            seen,
            severity="high",
            category="Upload",
            title="Upload flow without obvious server-side size limit",
            file=rel,
            line=line,
            evidence=evidence or "Upload-related code detected",
            recommendation="Enforce server-side file size, image dimension, and request body limits before accepting uploads.",
            policy="上传必须限制文件大小、图片尺寸和请求体大小。",
        )

    if not has_type_check:
        add_finding(
            findings,
            seen,
            severity="high",
            category="Upload",
            title="Upload flow without obvious MIME/magic-byte validation",
            file=rel,
            line=line,
            evidence=evidence or "Upload-related code detected",
            recommendation="Validate extension, MIME, and magic bytes server-side; re-encode images and reject unexpected formats.",
            policy="上传不能只看文件名，必须服务端校验类型和内容。",
        )

    public_patterns = [
        r"(?i)public-read",
        r"(?i)makePublic\s*\(",
        r"(?i)getPublicUrl\s*\(",
        r"(?i)publicUrl",
        r"(?i)acl\s*[:=]\s*['\"]public",
        r"(?i)bucket\([^\)]*public",
        r"(?i)storage\.from\([^\)]*\)\.getPublicUrl",
    ]
    public_line, public_evidence = find_first_line(text, public_patterns)
    if public_evidence and not has_private_access:
        add_finding(
            findings,
            seen,
            severity="blocker",
            category="Upload",
            title="Upload/storage may create permanent public URLs",
            file=rel,
            line=public_line,
            evidence=public_evidence,
            recommendation="Use private buckets, short-lived signed URLs, permission checks, anti-hotlinking, and moderation before public display.",
            policy="图片/文件上传不能默认变公共图床。",
        )
    elif public_evidence:
        add_finding(
            findings,
            seen,
            severity="high",
            category="Upload",
            title="Public upload URL pattern requires review",
            file=rel,
            line=public_line,
            evidence=public_evidence,
            recommendation="Confirm public access is intentional, moderated, rate-limited, logged, and revocable.",
            policy="公开文件访问必须可控、可撤销、可追溯。",
        )

    if not has_moderation and has_any(lower, ["image", "avatar", "photo", "picture", "图片", "头像"]):
        add_finding(
            findings,
            seen,
            severity="high",
            category="Upload",
            title="Image upload without obvious moderation or quarantine",
            file=rel,
            line=line,
            evidence=evidence or "Image upload-related code detected",
            recommendation="Add moderation/quarantine state before public display, plus admin takedown and audit logs.",
            policy="图片公开前需要审核、隔离或高风险隐藏策略。",
        )


def scan_ugc(text: str, rel: str, findings: List[Finding], seen: set) -> None:
    # Avoid treating every HTTP POST route as UGC. Require profile/comment/message/avatar-like signals.
    ugc_regex = re.compile(
        r"(?i)(comment|comments|nickname|displayName|bio\b|profile|review|guestbook|avatar|"
        r"user[_-]?content|userMessage|messageText|wallMessage|ugc|评论|昵称|简介|留言|许愿|头像)"
    )
    if not ugc_regex.search(text):
        return
    # Reduce false positives: require either route/mutation style code or rendering/public-display style code.
    mutation_or_public = has_any(
        text,
        ["create", "insert", "save", "submit", "render", "innerhtml", "dangerouslysetinnerhtml", "publish", "visible", "公开", "展示", "发布"],
    )
    if not mutation_or_public:
        return

    lower = text.lower()
    has_moderation = has_any(lower, ["moderation", "moderate", "approve", "approved", "pending", "hidden", "review", "reject", "ban", "takedown", "sanitize", "xss", "dompurify", "escape", "审核", "隐藏", "下架", "封禁", "风控"])
    has_rate = has_any(lower, ["ratelimit", "rate_limit", "throttle", "limit", "quota", "cooldown", "spam", "频率", "限速"])
    line, evidence = find_first_line(text, [r"(?i)(comment|nickname|displayName|bio\b|profile|review|guestbook|avatar|user[_-]?content|userMessage|messageText|ugc|评论|昵称|简介|留言|头像)[^\n]{0,120}"])

    if not has_moderation:
        add_finding(
            findings,
            seen,
            severity="high",
            category="UGC",
            title="UGC/public profile content without obvious moderation/takedown state",
            file=rel,
            line=line,
            evidence=evidence or "UGC-related code detected",
            recommendation="Add pending/hidden/rejected/visible states, spam/link/XSS filtering, admin takedown, ban, and audit logs before public display.",
            policy="公开 UGC 不能提交即展示，至少高风险内容先隐藏并可下架。",
        )

    if not has_rate:
        add_finding(
            findings,
            seen,
            severity="medium",
            category="UGC",
            title="UGC flow without obvious anti-spam rate controls",
            file=rel,
            line=line,
            evidence=evidence or "UGC-related code detected",
            recommendation="Add per-user/IP/device rate limits, length/link limits, duplicate detection, and new-user quotas.",
            policy="UGC 需要限频、长度限制和反垃圾策略。",
        )

    if re.search(r"dangerouslySetInnerHTML|innerHTML\s*=|v-html\s*=", text):
        line, evidence = find_first_line(text, [r"dangerouslySetInnerHTML[^\n]{0,120}", r"innerHTML\s*=[^\n]{0,120}", r"v-html\s*=[^\n]{0,120}"])
        add_finding(
            findings,
            seen,
            severity="high",
            category="UGC",
            title="User content may be rendered as raw HTML",
            file=rel,
            line=line,
            evidence=evidence,
            recommendation="Use strict HTML sanitization/escaping with an allowlist. Avoid raw HTML rendering for UGC.",
            policy="UGC 渲染必须防 XSS，富文本使用白名单清洗。",
        )


def scan_ai(text: str, rel: str, findings: List[Finding], seen: set) -> None:
    ai_regex = re.compile(
        r"(?i)(openai|anthropic|gemini|chat\.completions|responses\.create|system[_ -]?prompt|"
        r"\bllm\b|tool_calls|function_call|@ai-sdk|\buseChat\b|\bgenerateText\b|\bstreamText\b|模型|提示词)"
    )
    if not ai_regex.search(text):
        return
    # Avoid every README mention. Require code-y signals unless file looks like config.
    if rel.lower().endswith((".md", ".txt")) and not has_any(text, ["OPENAI_API_KEY", "system prompt", "tool_calls", "function_call", "@ai-sdk"]):
        return

    lower = text.lower()
    line, evidence = find_first_line(text, [r"(?i)(openai|anthropic|gemini|chat\.completions|responses\.create|system[_ -]?prompt|tool_calls|function_call|\bllm\b|@ai-sdk|\buseChat\b|\bgenerateText\b|\bstreamText\b|模型|提示词)[^\n]{0,140}"])

    if is_client_path(rel, text) and has_any(lower, ["openai", "anthropic", "gemini", "api_key", "apikey", "dangerouslyallowbrowser", "system prompt", "system_prompt", "@ai-sdk"]):
        add_finding(
            findings,
            seen,
            severity="blocker",
            category="AI",
            title="AI provider usage or system prompt appears in client-side code",
            file=rel,
            line=line,
            evidence=evidence or "AI-related client code detected",
            recommendation="Move model calls, system prompts, provider keys, and internal rules to server-side code. Browser clients should call your backend only.",
            policy="AI 密钥、系统提示和内部规则必须放在服务端。",
        )

    has_moderation = has_any(lower, ["moderation", "safety", "guardrail", "filter", "policy", "blocked", "审核", "过滤", "安全"])
    if not has_moderation:
        add_finding(
            findings,
            seen,
            severity="high",
            category="AI",
            title="AI flow without obvious input/output safety review",
            file=rel,
            line=line,
            evidence=evidence or "AI-related code detected",
            recommendation="Add input filtering, output moderation, refusal handling, audit logs, prompt-injection tests, and cost limits.",
            policy="AI 聊天不能只靠提示词自觉，输入输出都要服务端策略控制。",
        )

    if has_any(lower, ["tool_calls", "function_call", "execute", "exec(", "child_process", "shell", "sendemail", "sendsms", "delete", "writefile", "readfile", "fetch("]):
        if not has_any(lower, ["allowlist", "permission", "approve", "approval", "scope", "audit", "policy", "权限", "审批", "审计"]):
            add_finding(
                findings,
                seen,
                severity="blocker",
                category="AI",
                title="AI tool/function flow without obvious permission or approval boundary",
                file=rel,
                line=line,
                evidence=evidence or "AI tool-related code detected",
                recommendation="Add explicit tool allowlists, parameter validation, least privilege, audit logs, and human approval for sensitive tools.",
                policy="AI Agent 工具调用必须最小权限、可审计、敏感动作需审批。",
            )

    if not has_any(lower, ["ratelimit", "rate_limit", "quota", "budget", "limit", "usage", "cost", "token", "限速", "预算", "成本"]):
        add_finding(
            findings,
            seen,
            severity="medium",
            category="AI",
            title="AI flow without obvious cost/rate controls",
            file=rel,
            line=line,
            evidence=evidence or "AI-related code detected",
            recommendation="Add per-user rate limits, token budgets, usage logging, abnormal cost alerts, and a kill switch.",
            policy="AI 成本型功能需要用户级配额、预算和异常报警。",
        )


def scan_auth_routes(text: str, rel: str, findings: List[Finding], seen: set) -> None:
    lower_rel = rel.lower()
    lower = text.lower()
    route_like = any(marker in lower_rel for marker in ["/api/", "routes", "controllers", "route.", "server", "handler"])
    mutating = re.search(r"(?i)(app\.(post|put|patch|delete)|router\.(post|put|patch|delete)|method\s*[:=]\s*['\"](POST|PUT|PATCH|DELETE)|export\s+async\s+function\s+(POST|PUT|PATCH|DELETE)|@(Post|Put|Patch|Delete))", text)
    if not (route_like or mutating):
        return
    if not mutating:
        return

    auth_terms = ["auth", "session", "jwt", "passport", "clerk", "nextauth", "supabase.auth", "firebase.auth", "requireuser", "requireauth", "isauthenticated", "currentuser", "getserverSession", "middleware", "permission", "role", "owner", "tenant", "csrf", "权限", "鉴权", "认证", "授权"]
    line = line_for_offset(text, mutating.start())
    evidence = mutating.group(0)
    if not has_any(lower, auth_terms):
        add_finding(
            findings,
            seen,
            severity="high",
            category="API/Auth",
            title="Mutating route without obvious authentication/authorization",
            file=rel,
            line=line,
            evidence=evidence,
            recommendation="Require server-side authentication, role/owner checks, object-level authorization, and CSRF protections where applicable.",
            policy="所有写接口必须有服务端认证、授权和对象级权限。",
        )
    elif not has_any(lower, ["owner", "tenant", "permission", "role", "policy", "authorize", "can(", "where", "user.id", "userid", "ownerid", "teamid", "组织", "租户", "所有者"]):
        add_finding(
            findings,
            seen,
            severity="medium",
            category="API/Auth",
            title="Mutating route has auth signals but object-level authorization is not obvious",
            file=rel,
            line=line,
            evidence=evidence,
            recommendation="Verify users cannot change IDs to access/modify others' resources. Add owner/tenant/role checks and tests.",
            policy="鉴权后仍需要对象级权限，防 IDOR/越权。",
        )


def scan_monitoring_ops(text: str, rel: str, findings: List[Finding], seen: set) -> None:
    # Positive info in likely ops/admin files. Not a failure by itself.
    if has_any(rel, ["admin", "moderation", "audit", "alert", "monitor", "observability", "ops"]):
        if has_any(text, ["takedown", "ban", "suspend", "rollback", "alert", "audit", "下架", "封禁", "报警", "告警", "审计", "回滚"]):
            line, evidence = find_first_line(text, [r"(?i)(takedown|ban|suspend|rollback|alert|audit|下架|封禁|报警|告警|审计|回滚)[^\n]{0,120}"])
            add_finding(
                findings,
                seen,
                severity="info",
                category="Monitoring/Ops",
                title="Ops/admin control signal found",
                file=rel,
                line=line,
                evidence=evidence,
                recommendation="Verify this control is wired to production alerts, audit logs, and accountable owners.",
                policy="公开上线需要下架、封禁、报警、回滚和追溯能力。",
            )


def scan_project(root: Path, max_file_size: int) -> Tuple[List[Finding], Dict[str, int]]:
    findings: List[Finding] = []
    seen = set()
    stats = {"files_scanned": 0, "bytes_scanned": 0}

    for path in iter_files(root, max_file_size=max_file_size):
        rel = normalize_path(path, root)
        try:
            text = read_text(path)
        except OSError:
            continue
        stats["files_scanned"] += 1
        stats["bytes_scanned"] += len(text.encode("utf-8", errors="ignore"))

        scan_secrets(text, rel, findings, seen)
        scan_cors_debug_sql(text, rel, findings, seen)
        scan_sms_otp(text, rel, findings, seen)
        scan_uploads(text, rel, findings, seen)
        scan_ugc(text, rel, findings, seen)
        scan_ai(text, rel, findings, seen)
        scan_auth_routes(text, rel, findings, seen)
        scan_monitoring_ops(text, rel, findings, seen)

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.category, f.file, f.line))
    # Re-number after sorting.
    for index, finding in enumerate(findings, start=1):
        finding.id = f"RSG-{index:04d}"
    return findings, stats


def severity_counts(findings: Sequence[Finding]) -> Dict[str, int]:
    counts = {key: 0 for key in ["blocker", "high", "medium", "low", "info"]}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def determine_verdict(findings: Sequence[Finding]) -> str:
    counts = severity_counts(findings)
    if counts.get("blocker", 0) > 0:
        return "BLOCK"
    if counts.get("high", 0) > 0:
        return "PASS_WITH_CONDITIONS"
    return "PASS"


def markdown_table_row(values: Sequence[str]) -> str:
    escaped = []
    for value in values:
        value = str(value).replace("\n", " ").replace("|", "\\|")
        escaped.append(value)
    return "| " + " | ".join(escaped) + " |"


def render_markdown(findings: Sequence[Finding], stats: Dict[str, int], root: Path) -> str:
    counts = severity_counts(findings)
    verdict = determine_verdict(findings)
    lines: List[str] = []
    lines.append("# Security Release Review")
    lines.append("")
    lines.append(f"Scope: `{root}`")
    lines.append(f"Files scanned: `{stats.get('files_scanned', 0)}`")
    lines.append(f"Bytes scanned: `{stats.get('bytes_scanned', 0)}`")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append(f"`{verdict}`")
    lines.append("")
    lines.append("Severity counts:")
    lines.append("")
    lines.append(markdown_table_row(["Severity", "Count"]))
    lines.append(markdown_table_row(["---", "---"]))
    for sev in ["blocker", "high", "medium", "low", "info"]:
        lines.append(markdown_table_row([sev.upper(), str(counts.get(sev, 0))]))
    lines.append("")

    blockers = [f for f in findings if f.severity in {"blocker", "high"}]
    lines.append("## Top Release Blockers / High Risks")
    lines.append("")
    if blockers:
        lines.append(markdown_table_row(["ID", "Severity", "Category", "Evidence", "Recommendation"]))
        lines.append(markdown_table_row(["---", "---", "---", "---", "---"]))
        for f in blockers[:25]:
            lines.append(markdown_table_row([f.id, f.severity.upper(), f.category, f"`{f.file}:{f.line}` {f.title}. {f.evidence}", f.recommendation]))
    else:
        lines.append("No blocker/high findings from the heuristic scanner. Manual review is still required.")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if findings:
        lines.append(markdown_table_row(["ID", "Severity", "Category", "File", "Line", "Title", "Evidence", "Recommendation", "Policy"]))
        lines.append(markdown_table_row(["---", "---", "---", "---", "---", "---", "---", "---", "---"]))
        for f in findings:
            lines.append(
                markdown_table_row(
                    [
                        f.id,
                        f.severity.upper(),
                        f.category,
                        f.file,
                        str(f.line),
                        f.title,
                        f.evidence,
                        f.recommendation,
                        f.policy,
                    ]
                )
            )
    else:
        lines.append("No findings generated by the heuristic scanner.")
    lines.append("")

    lines.append("## Manual Bad Actor Questions")
    lines.append("")
    lines.append("Use these questions to complete the human/agent review; do not rely only on this script:")
    lines.append("")
    for q in [
        "Can SMS/email/AI/payment/upload endpoints be abused as cost amplifiers?",
        "Can UGC fields such as nickname, avatar, bio, comments, or posts be used for ads or illegal content?",
        "Can uploads become a public file host or make the platform domain carry illegal files?",
        "Can AI chat reveal system prompts, secrets, hidden policies, or misuse tools?",
        "Can users modify IDs to access or change another user's resources?",
        "Can admins detect, takedown, ban, rollback, and trace incidents quickly?",
    ]:
        lines.append(f"- [ ] {q}")
    lines.append("")

    lines.append("## Notes")
    lines.append("")
    lines.append("This report was generated by a dependency-free heuristic scanner. It should be treated as a triage aid, not a complete security assessment. Verify all findings in context and add project-specific tests before launch.")
    lines.append("")
    return "\n".join(lines)


def write_outputs(findings: Sequence[Finding], stats: Dict[str, int], root: Path, out: Optional[Path], json_out: Optional[Path]) -> None:
    if out:
        out.write_text(render_markdown(findings, stats, root), encoding="utf-8")
    if json_out:
        payload = {
            "verdict": determine_verdict(findings),
            "stats": stats,
            "severity_counts": severity_counts(findings),
            "findings": [asdict(f) for f in findings],
        }
        json_out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Release Safety Gate heuristic scanner")
    parser.add_argument("--root", default=".", help="Project root to scan. Default: current directory")
    parser.add_argument("--out", default="", help="Markdown report output path")
    parser.add_argument("--json", default="", help="JSON findings output path")
    parser.add_argument("--fail-on", default="none", choices=["none", "info", "low", "medium", "high", "blocker"], help="Exit non-zero when findings at or above this severity exist")
    parser.add_argument("--max-file-size", type=int, default=1024 * 1024, help="Max bytes per file to scan. Default: 1048576")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    root = Path(args.root).resolve()
    if not root.exists():
        print(f"Root does not exist: {root}", file=sys.stderr)
        return 2

    findings, stats = scan_project(root, max_file_size=args.max_file_size)
    out = Path(args.out).resolve() if args.out else None
    json_out = Path(args.json).resolve() if args.json else None
    write_outputs(findings, stats, root, out, json_out)

    counts = severity_counts(findings)
    verdict = determine_verdict(findings)
    print(f"Release Safety Gate verdict: {verdict}")
    print("Findings: " + ", ".join(f"{sev}={counts.get(sev, 0)}" for sev in ["blocker", "high", "medium", "low", "info"]))
    if out:
        print(f"Markdown report: {out}")
    if json_out:
        print(f"JSON findings: {json_out}")

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
