import os

import pytest
from fastapi.testclient import TestClient

from pagerlens import api, embedcfg, vault
from pagerlens import chat as chat_mod

os.environ.setdefault("PAGERLENS_HOUSEKEEPING", "false")   # no background thread in tests: they call the pass themselves


@pytest.fixture(scope="session")
def client():
    # The MCP session manager can only be started once per process, so share one client.
    with TestClient(api.app) as c:
        yield c


@pytest.fixture(autouse=True)
def _clean_process_state(client):
    client.cookies.clear()  # the client is shared: never let one test's login leak into another
    embedcfg.reset()
    chat_mod.reset_tool_choice()
    vault.lock()
    yield
    client.cookies.clear()
    embedcfg.reset()
    chat_mod.reset_tool_choice()
    vault.lock()
