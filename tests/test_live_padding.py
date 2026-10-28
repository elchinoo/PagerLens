"""The SSE stream opens with comment padding so buffering proxies flush the first frame (no database needed)."""
from pagerlens import live


def test_padding_is_a_2kb_sse_comment_line():
    assert 2048 <= len(live.PADDING) <= 2100
    assert live.PADDING.startswith(":") and live.PADDING.endswith("\n") and live.PADDING.count("\n") == 1   # one comment line: clients ignore it
