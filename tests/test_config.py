from pagerlens.config import get_settings

_VARS = ("DATABASE_URL", "DB_EXTERNAL_DSN", "PSQL_CONNECTION_STRING", "PAGERLENS_API_KEY", "PAGERLENS_API_KEY_FILE")


def _clean(monkeypatch):
    for v in _VARS:
        monkeypatch.delenv(v, raising=False)


def test_database_url_precedence(monkeypatch):
    _clean(monkeypatch)
    assert get_settings().database_url == ""  # libpq then uses PG* variables
    monkeypatch.setenv("PSQL_CONNECTION_STRING", "psql")
    assert get_settings().database_url == "psql"
    monkeypatch.setenv("DB_EXTERNAL_DSN", "ext")
    assert get_settings().database_url == "ext"
    monkeypatch.setenv("DATABASE_URL", "url")
    assert get_settings().database_url == "url"


def test_api_key_from_env_then_file(monkeypatch, tmp_path):
    _clean(monkeypatch)
    f = tmp_path / "key"
    f.write_text("from-file\nignored\n")
    monkeypatch.setenv("PAGERLENS_API_KEY_FILE", str(f))
    assert get_settings().api_key == "from-file"  # pragma: allowlist secret
    monkeypatch.setenv("PAGERLENS_API_KEY", "from-env")
    assert get_settings().api_key == "from-env"  # pragma: allowlist secret
    monkeypatch.delenv("PAGERLENS_API_KEY")
    monkeypatch.setenv("PAGERLENS_API_KEY_FILE", str(tmp_path / "missing"))
    assert get_settings().api_key == ""


def test_llm_key_from_file(monkeypatch, tmp_path):
    for v in ("LLM_API_KEY", "LLM_API_KEY_FILE"):
        monkeypatch.delenv(v, raising=False)
    f = tmp_path / "llm"
    f.write_text("file-llm-key\n")
    monkeypatch.setenv("LLM_API_KEY_FILE", str(f))
    assert get_settings().llm_api_key == "file-llm-key"  # pragma: allowlist secret
    monkeypatch.setenv("LLM_API_KEY", "env-llm-key")
    assert get_settings().llm_api_key == "env-llm-key"  # pragma: allowlist secret
