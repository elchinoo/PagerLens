"""The browser code without a browser: every module parses, and the fake-DOM checks under tests/ui pass (needs node and the sibling kit)."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


@pytest.mark.parametrize("js", sorted((ROOT / "src/pagerlens/static").glob("*.js")), ids=lambda p: p.name)
def test_every_ui_module_parses(js):
    r = subprocess.run([NODE, "--input-type=module", "--check"], input=js.read_text(), capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(not (ROOT.parent / "agentpg-kit/src/apgkit/static").is_dir(), reason="the sibling agentpg-kit checkout is not present")
@pytest.mark.parametrize("script", ["dashboard_typing.mjs", "incident_typing.mjs", "housekeeping_typing.mjs"])
def test_fake_dom_checks(script):
    r = subprocess.run([NODE, str(ROOT / "tests/ui" / script)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.startswith("ok"), r.stdout + r.stderr
