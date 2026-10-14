"""Tiny key/value store for instance settings (table app_setting)."""


def get(conn, key: str) -> str | None:
    row = conn.execute("SELECT value FROM app_setting WHERE key=%s", (key,)).fetchone()
    return row["value"] if row else None


def put(conn, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO app_setting (key, value) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
        (key, value),
    )


def delete(conn, *keys: str) -> None:
    conn.execute("DELETE FROM app_setting WHERE key = ANY(%s)", (list(keys),))
