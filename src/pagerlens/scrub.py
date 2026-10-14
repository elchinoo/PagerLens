"""Redaction and normalisation applied to every log line BEFORE it is stored, so personal data and secrets
never reach the database, the UI, the MCP tools or an LLM.

Redaction is best effort and pattern based: it is a safety net, not a licence to log secrets.
"""
import re

_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*)(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"), r"\1\2 [REDACTED]"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 [REDACTED]"),
    (re.compile(r"\b(?:sk|pk|rk|ghp|gho|ghs|xox[abprs]|AKIA|ASIA)[-_A-Za-z0-9]{12,}"), "[REDACTED-KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED-JWT]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)(\s*[=:]\s*)\S+"), r"\1\2[REDACTED]"),
    (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "[EMAIL]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[CARD]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP]"),
    (re.compile(r"(?i)\b(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}\b"), "[IP]"),
    (re.compile(r"\+\d[\d ()-]{8,}\d"), "[PHONE]"),
]

MAX_MESSAGE = 2000
_LEVELS = {"debug", "info", "warn", "warning", "error", "fatal", "critical"}


def scrub(text: str) -> str:
    text = text[:MAX_MESSAGE]
    for pattern, repl in _RULES:
        text = pattern.sub(repl, text)
    return text


def scrub_value(value, depth: int = 0):
    """Scrub strings inside a JSON-like structure (log fields)."""
    if depth > 4:
        return "[TRUNCATED]"
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, dict):
        return {str(k)[:60]: scrub_value(v, depth + 1) for k, v in list(value.items())[:30]}
    if isinstance(value, list):
        return [scrub_value(v, depth + 1) for v in value[:30]]
    return value if isinstance(value, (int, float, bool)) or value is None else str(value)[:200]


def normalise_level(level: str) -> str:
    level = (level or "info").strip().lower()
    level = {"warning": "warn", "critical": "fatal"}.get(level, level)
    return level if level in _LEVELS else "info"


_SIG_RULES = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<hex>"),
    (re.compile(r"\b[0-9a-f]{16,}\b", re.I), "<hex>"),
    (re.compile(r"\d+"), "<n>"),
]


def signature(message: str) -> str:
    """Group 'the same error' across requests: numbers, ids and hex blobs are replaced by placeholders."""
    sig = message.strip().splitlines()[0] if message.strip() else ""
    for pattern, repl in _SIG_RULES:
        sig = pattern.sub(repl, sig)
    return re.sub(r"\s+", " ", sig)[:200]
