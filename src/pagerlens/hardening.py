"""Read-only and AI access hardening, applied after every migration (agentpg-kit `masking`, AgentPG's `a1p_readonly` role).

Who is protected: a database user made with `agentpg db-users create --permission read` and AgentPG's restricted MCP server both
run as members of the group role `a1p_readonly`. AgentPG gives that role SELECT on every new table by default, so after each
migration this hook

1. replaces the base tables that hold personal data or free text with a masked view (`<table>_masked`): names become an initial,
   e-mail addresses, API-key-like strings and JWTs inside free text are redacted, everything operational (ids, times, versions,
   metric values, statuses, severities, categories) stays readable;
2. takes SELECT away, with no view at all, from every table that holds secrets, hashes, ciphertext or the simulator's answer key.

It only changes what `a1p_readonly` can read: the application's own connection (the table owner) is unaffected. It must run as the
table owner, skips quietly where the role does not exist (plain Postgres in dev and CI), and is idempotent.
"""
import logging
from typing import Any

import psycopg
from apgkit import masking
from psycopg import sql

log = logging.getLogger("pagerlens.hardening")

READONLY_ROLE = masking.READONLY_ROLE

# Developer-written SQL (never user input). Mirrors the ingest-time `scrub.py` for the cases that matter to a reader of free text:
# e-mail addresses, key-like tokens (sk-, pk-, ghp_, AKIA..., pl_ API tokens) and JWTs.
_EMAIL = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+"
_KEY = r"\m(sk|pk|rk|ghp|gho|ghs|AKIA|ASIA|pl)[-_]?[A-Za-z0-9]{16,}"
_JWT = r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"


def scrub_expr(column: str, *, jsonb: bool = False) -> str:
    """SQL expression that redacts e-mail addresses, key-like strings and JWTs inside a text (or jsonb) column."""
    expr = f'"{column}"::text'
    for pattern, repl in ((_JWT, "[REDACTED-JWT]"), (_KEY, "[REDACTED-KEY]"), (_EMAIL, "[EMAIL]")):
        expr = f"regexp_replace({expr}, '{pattern}', '{repl}', 'g')"
    return f"({expr})::jsonb" if jsonb else expr


# table -> (view, {column: rule}). Columns that are not listed are not exposed (the embedding vectors, for one).
MASKED: dict[str, tuple[str, dict[str, str]]] = {
    "incident": ("incident_masked", {
        "id": "pass", "service_id": "pass", "service_name": "pass", "status": "pass", "severity": "pass", "fingerprint": "pass",
        "detected_at": "pass", "resolved_at": "pass", "created_at": "pass", "root_cause_category": "pass",
        "title": scrub_expr("title"), "symptom": scrub_expr("symptom"), "root_cause_note": scrub_expr("root_cause_note")}),
    "incident_note": ("incident_note_masked", {
        "id": "pass", "incident_id": "pass", "created_at": "pass", "author": "initial", "body": scrub_expr("body")}),
    "alert": ("alert_masked", {
        "id": "pass", "service_id": "pass", "incident_id": "pass", "source": "pass", "severity": "pass", "fired_at": "pass",
        "name": scrub_expr("name"), "summary": scrub_expr("summary"), "labels": scrub_expr("labels", jsonb=True)}),
    "deploy": ("deploy_masked", {
        "id": "pass", "service_id": "pass", "version": "pass", "git_sha": "pass", "deployed_at": "pass",
        "author": "initial", "summary": scrub_expr("summary")}),
    "service": ("service_masked", {
        "id": "pass", "name": "pass", "tier": "pass", "depends_on": "pass", "created_at": "pass",
        "owner": scrub_expr("owner"), "description": scrub_expr("description")}),
    "log_event": ("log_event_masked", {
        "id": "pass", "service_id": "pass", "ts": "pass", "level": "pass", "signature": "pass",
        "message": scrub_expr("message"), "fields": scrub_expr("fields", jsonb=True)}),
    # tuning proposals name people who decided and statements that show the workload: names become an initial, text is scrubbed
    "tuning_proposal": ("tuning_proposal_masked", {
        "id": "pass", "source": "pass", "target": "pass", "applicable": "pass", "status": "pass", "motivating_queryid": "pass",
        "decided_at": "pass", "applied_at": "pass", "created_at": "pass", "before_timing": "pass", "after_timing": "pass",
        "decided_by": "initial", "applied_by": "initial", "statement": scrub_expr("statement"), "rationale": scrub_expr("rationale"),
        "estimated_benefit": scrub_expr("estimated_benefit"), "motivating_query": scrub_expr("motivating_query"),
        "decision_note": scrub_expr("decision_note"), "error": scrub_expr("error")}),
    "tuning_audit": ("tuning_audit_masked", {
        "id": "pass", "proposal_id": "pass", "action": "pass", "at": "pass", "actor": "initial", "detail": scrub_expr("detail")}),
}

# Secrets, hashes, ciphertext, sessions and the simulator's answer key: no view, no access.
DENIED: tuple[str, ...] = (
    "app_setting",      # kit settings store: the vault's wrapped key and salt, the admin password hash, the static-key state
    "llm_account",      # provider accounts: api_key_enc (ciphertext) and api_key_last4
    "api_token",        # sha256 of the ingest, read, metrics and full tokens
    "web_session",      # session token hashes, subject, e-mail, id_token_hint
    "oidc_login",       # in-flight single-sign-on state, nonce and PKCE verifier
    "sim_truth",        # the Lab's hidden answer: an AI assistant reading it would see the cause before investigating
)


def _exists(conn: psycopg.Connection, table: str) -> bool:
    return conn.execute("SELECT to_regclass(%s) IS NOT NULL AS ok", (f'public."{table}"',)).fetchone()["ok"]


def deny(conn: psycopg.Connection, table: str, role: str = READONLY_ROLE) -> dict[str, Any]:
    """REVOKE SELECT on `table` from `role` and verify it (a non-owner REVOKE only warns). Idempotent; skips a missing role or table."""
    conn.commit()
    prev, conn.autocommit = conn.autocommit, True
    try:
        if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
            return {"table": table, "applied": False, "reason": f"role {role} does not exist"}
        if not _exists(conn, table):
            return {"table": table, "applied": False, "reason": "table does not exist"}
        conn.execute(sql.SQL("REVOKE SELECT ON {} FROM {}").format(sql.Identifier("public", table), sql.Identifier(role)))
        readable = conn.execute("SELECT has_table_privilege(%s, %s, 'SELECT') AS ok", (role, f'public."{table}"')).fetchone()["ok"]
    finally:
        conn.autocommit = prev
    if readable:
        log.warning("%s can still read %s (not the owner, or PUBLIC has SELECT)", role, table)
    return {"table": table, "applied": not readable, "reason": "still readable by the role" if readable else ""}


def apply(conn: psycopg.Connection, role: str = READONLY_ROLE) -> dict[str, Any]:
    """The after-migrate hook: masked views for personal data, REVOKE for secrets. Returns a summary (also useful in tests)."""
    out: dict[str, Any] = {"masked": {}, "denied": {}}
    conn.commit()
    if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
        log.info("read-only hardening skipped: role %s does not exist", role)
        return out                           # plain Postgres (dev, CI): nothing to protect
    for table, (view, columns) in MASKED.items():
        if not _exists(conn, table):
            continue
        out["masked"][table] = masking.mask_view(conn, table, view, columns, readonly_role=role)
    for table in DENIED:
        out["denied"][table] = deny(conn, table, role)
    unsafe = [t for t, r in {**out["masked"], **out["denied"]}.items() if not r["applied"]]
    if unsafe:
        log.warning("read-only hardening incomplete for: %s (run migrations as the table owner)", ", ".join(unsafe))
    return out
