"""Row MACs: a database WRITE without the vault data key cannot plant a provider account, a runbook or the embedding choice.

Rows that grant access or carry trust carry `mac`, an HMAC under a subkey of the vault data key (agentpg-kit `Vault.row_mac`) over the
columns listed in FIELDS. Reads that feed a decision call `verify`/`valid`; a row with a missing or wrong MAC is treated exactly like a
missing row. Writes sign in the same transaction (`seal`, `update`). Browser sessions and API tokens are signed by the kit itself.

Enforced only while the vault is unlocked (always, with sealed boot). While it is locked (dev, tests, no vault) nothing is checked, and
rows written meanwhile carry no MAC until `pagerlens adopt-rowmacs` signs them.

Limits (see README, "Row MACs"): a copied older authentic row replays from a backup; deleting rows is still possible; unsigned rows are
ignored, so an attacker's write can at worst deny service or crowd out genuine rows; columns not listed here are not covered.
"""
import json
import logging
import threading

from prometheus_client import Counter

from . import core
from . import settings_store as store

log = logging.getLogger("pagerlens.security")

# What decides authority. Display names, last4, timestamps and embeddings are deliberately NOT signed (they change often or are derived).
FIELDS: dict[str, tuple[str, ...]] = {
    "llm_account": ("id", "provider", "base_url", "api_key_enc", "chat_model", "embedding_model", "embedding_dim"),
    "runbook": ("id", "title", "category", "service", "body"),
    "app_setting": ("key", "value"),
}
PK: dict[str, str] = {"llm_account": "id", "runbook": "id", "app_setting": "key"}
TABLES = tuple(FIELDS)
# app_setting also holds the kit's own keys (vault wraps, admin password hash) and bookkeeping; only these keys decide something.
SIGNED_SETTINGS = ("embedding_account_id",)

tampered = Counter("pagerlens_tampered_rows_total", "Rows refused because their MAC is missing or wrong", ["table"],
                   registry=core.metrics.registry)
_reported: set[tuple[str, str]] = set()
_reported_lock = threading.Lock()


def enforced() -> bool:
    return core.vault.is_unlocked()


def _canon(value) -> str:
    return "\x00" if value is None else str(value)       # None is distinct from the empty string


def _fields(table: str, row: dict) -> list[str]:
    return [_canon(row[c]) for c in FIELDS[table]]


def sign_row(table: str, row: dict) -> str:
    """The MAC for `row` (a dict holding at least the signed columns of `table`). Raises VaultLocked when the vault is locked."""
    return core.vault.row_mac(table, *_fields(table, row))


def _covered(table: str, row: dict) -> bool:
    return table != "app_setting" or row.get("key") in SIGNED_SETTINGS


def verify(table: str, row: dict | None) -> bool:
    """False for a missing row, or (while the vault is unlocked) a row whose MAC is missing or wrong. A refused row is logged once per
    process with the table and key only, and counted. While the vault is locked nothing is checked."""
    if not row:
        return False
    if not _covered(table, row) or not enforced():
        return True
    try:
        if core.vault.check_row_mac(table, row.get("mac"), *_fields(table, row)):
            return True
    except Exception:  # noqa: BLE001  (locked mid-call, odd column types: fail closed)
        return False
    key = (table, str(row[PK[table]]))
    tampered.labels(table).inc()
    with _reported_lock:
        first = key not in _reported
        _reported.add(key)
    if first:
        log.warning("row refused, MAC missing or wrong: table=%s key=%s (a legitimate row written before row MACs needs "
                    "`pagerlens adopt-rowmacs`)", *key)
    return False


def valid(table: str, rows: list[dict]) -> list[dict]:
    return [r for r in rows if verify(table, r)]


def without_mac(row: dict) -> dict:
    return {k: v for k, v in row.items() if k != "mac"}


def seal(conn, table: str, where: str, params: tuple = ()) -> int:
    """Sign the rows of `table` matching `where`, in the caller's transaction. ONLY for rows this process has just written (or `adopt`):
    it signs whatever the row holds now. With the vault locked the MAC is cleared (the row is ignored once the vault opens, until adopted)."""
    rows = conn.execute(f"SELECT * FROM {table} WHERE {where}", params).fetchall()           # noqa: S608  (table is a constant of this module)
    unlocked = enforced()
    n = 0
    for r in rows:
        if not _covered(table, r):
            continue
        conn.execute(f"UPDATE {table} SET mac=%s WHERE {PK[table]}=%s",                      # noqa: S608
                     (sign_row(table, r) if unlocked else None, r[PK[table]]))
        n += 1
    return n


def update(conn, table: str, assignments: str, set_params: tuple, where: str, params: tuple = ()) -> int:
    """UPDATE ... SET `assignments` WHERE `where`, then re-sign the rows that carried a valid MAC BEFORE the change (a planted or edited
    row is never legitimised by an unrelated update). While the vault is locked the changed rows lose their MAC. Returns rows changed."""
    before = conn.execute(f"SELECT * FROM {table} WHERE {where} FOR UPDATE", params).fetchall()             # noqa: S608
    good = [r[PK[table]] for r in before if verify(table, r)]
    n = conn.execute(f"UPDATE {table} SET {assignments} WHERE {where}", (*set_params, *params)).rowcount     # noqa: S608
    for pk in good:
        seal(conn, table, f"{PK[table]}=%s", (pk,))
    return n


# --- app_setting -------------------------------------------------------------------------------------------------------------
def get_setting(conn, key: str) -> str | None:
    """A setting whose value decides something. A row that fails verification is treated as absent."""
    row = conn.execute("SELECT key, value, mac FROM app_setting WHERE key=%s", (key,)).fetchone()
    return row["value"] if row and verify("app_setting", row) else None


def put_setting(conn, key: str, value: str) -> None:
    """Write a signed setting in the caller's transaction."""
    store.put(conn, key, value)
    seal(conn, "app_setting", "key=%s", (key,))


# --- runbooks that ship with the app -----------------------------------------------------------------------------------------
def sign_builtin_runbooks(conn) -> int:
    """Sign unsigned runbooks whose text is EXACTLY one of the runbooks shipped in this release (simulator.RUNBOOKS). Safe without trusting
    the database: the content is compared with the code. Covers runbooks seeded while the vault was locked (sealed boot seeds before it
    unlocks) and those written before row MACs. A runbook with any other text stays unsigned (ignored) until `adopt-rowmacs`."""
    if not enforced():
        return 0
    from .simulator import RUNBOOKS

    shipped = {tuple(rb) for rb in RUNBOOKS}
    n = 0
    for r in conn.execute("SELECT id, title, category, service, body FROM runbook WHERE mac IS NULL").fetchall():
        if (r["title"], r["category"], r["service"], r["body"]) in shipped:
            n += seal(conn, "runbook", "id=%s", (r["id"],))
    return n


# --- data-key rotation (every MAC is under the old key's subkey) --------------------------------------------------------------
def _setting_where() -> tuple[str, tuple]:
    return "key = ANY(%s)", (list(SIGNED_SETTINGS),)


def snapshot(conn) -> dict:
    """Primary keys of every row that verifies now. Includes the kit's own web_session and api_token rows: their MACs also change with
    the data key and the kit does not re-sign them. Needs the vault unlocked."""
    snap: dict[str, list] = {}
    chk = core.vault.check_row_mac
    snap["web_session"] = [r["token_hash"] for r in conn.execute("SELECT * FROM web_session").fetchall()
                           if chk("web_session", r["mac"], r["token_hash"], r["subject"], r["name"], r["email"],
                                  json.dumps(sorted(r["roles"])), r["source"], int(r["expires_at"].timestamp()))]
    snap["api_token"] = [r["id"] for r in conn.execute("SELECT * FROM api_token WHERE revoked_at IS NULL").fetchall()
                         if chk("api_token", r["mac"], r["id"], r["name"], r["token_hash"], r["prefix"], r["scope"], 0)]
    for t in TABLES:
        rows = conn.execute(f"SELECT * FROM {t}").fetchall()             # noqa: S608
        snap[t] = [r[PK[t]] for r in rows if _covered(t, r) and verify(t, r)]
    return snap


def reseal(conn, snap: dict) -> int:
    """Sign again, under the new key, the rows that verified before the rotation (rows that did not stay unsigned)."""
    n = 0
    for token_hash in snap.pop("web_session", []):
        r = conn.execute("SELECT * FROM web_session WHERE token_hash=%s", (token_hash,)).fetchone()
        if r:
            conn.execute("UPDATE web_session SET mac=%s WHERE token_hash=%s", (core.local.session_mac(
                r["token_hash"], r["subject"], r["name"], r["email"], r["roles"], r["source"], r["expires_at"]), token_hash))
    for tid in snap.pop("api_token", []):
        r = conn.execute("SELECT * FROM api_token WHERE id=%s", (tid,)).fetchone()
        if r:
            conn.execute("UPDATE api_token SET mac=%s WHERE id=%s", (core.local.token_mac(
                r["id"], r["name"], r["token_hash"], r["prefix"], r["scope"], False), tid))
    for t, pks in snap.items():
        for pk in pks:
            n += seal(conn, t, f"{PK[t]}=%s", (pk,))
    return n


def rotate_data_key(conn, password: str | None) -> dict[str, int]:
    """`Vault.rotate_data_key` plus re-signing: the rows that verified under the old key are signed under the new one. The connection must
    be idle. Between the rotation's commit and the re-signing commit the rows are unsigned, so they are ignored (fail closed)."""
    snap = snapshot(conn)
    conn.rollback()                                            # rotate_data_key needs an idle connection
    counts = core.vault.rotate_data_key(conn, password=password)
    reseal(conn, snap)
    conn.commit()
    return counts


# --- adoption ----------------------------------------------------------------------------------------------------------------
def adopt(conn) -> dict[str, int]:
    """Sign every covered row that has no MAC (a database that existed before row MACs), including the kit's sessions and API tokens.
    TRUSTS THE DATABASE AS IT IS NOW. Needs the vault open."""
    if not enforced():
        raise RuntimeError("adopt needs an open vault")
    out = {t: seal(conn, t, "mac IS NULL" if t != "app_setting" else "mac IS NULL AND key = ANY(%s)",
                   () if t != "app_setting" else (list(SIGNED_SETTINGS),)) for t in TABLES}
    conn.commit()
    kit = core.local.adopt_rows(conn)                           # commits
    out["web_session"], out["api_token"] = kit["sessions"], kit["tokens"]
    return out


def clear_all(conn) -> None:
    """The data key is gone (vault reset): no MAC can verify any more. Cleared so nothing pretends to be signed."""
    conn.execute("UPDATE llm_account SET mac=NULL")
    conn.execute("UPDATE runbook SET mac=NULL")
    conn.execute("UPDATE app_setting SET mac=NULL")
