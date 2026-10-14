from pagerlens.scrub import normalise_level, scrub, scrub_value, signature


def test_pii_and_secrets_are_redacted():
    msg = ("user jane.doe@example.com from 203.0.113.9 paid with 4111 1111 1111 1111 "
           "Authorization: Bearer abcDEF123456789xyz password=hunter2 token=abc123")  # pragma: allowlist secret
    out = scrub(msg)
    for leaked in ("jane.doe", "203.0.113.9", "4111", "abcDEF123456789xyz", "hunter2", "abc123"):
        assert leaked not in out
    assert "[EMAIL]" in out and "[IP]" in out and "[CARD]" in out and out.count("[REDACTED]") >= 2


def test_keys_and_jwts_are_redacted():
    assert "sk-" not in scrub("key sk-abcdefghijklmnopqrstuvwx used")  # pragma: allowlist secret
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert "eyJ" not in scrub(f"token {jwt}")


def test_scrub_bounds_length_and_nested_fields():
    assert len(scrub("x" * 10_000)) == 2000
    out = scrub_value({"a": {"b": ["mail me at bob@example.org"]}, "n": 3})
    assert out == {"a": {"b": ["mail me at [EMAIL]"]}, "n": 3}
    assert scrub_value({"deep": {"a": {"b": {"c": {"d": {"e": "x"}}}}}})["deep"]["a"]["b"]["c"]["d"] == "[TRUNCATED]"


def test_levels_normalise():
    assert normalise_level("WARNING") == "warn" and normalise_level("Critical") == "fatal"
    assert normalise_level("weird") == "info" and normalise_level("") == "info"


def test_signature_groups_the_same_error():
    a = signature("timeout acquiring connection from pool (max=20, waiting=3)")
    b = signature("timeout acquiring connection from pool (max=20, waiting=17)")
    assert a == b and "<n>" in a
    assert signature("failed for 7f3c9a1e-1111-2222-3333-444455556666") == "failed for <uuid>"
