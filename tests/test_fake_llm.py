"""The demo stand-in model (scripts/fake_llm.py): still labelled, still deterministic, and its investigation behaviour is unchanged by the
Ask mode. (Its Ask answers through the real tools are tested in test_ask_db.py.)"""
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "fake_llm.py"


@pytest.fixture(scope="module")
def fake():
    spec = importlib.util.spec_from_file_location("fake_llm", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


INVESTIGATION_TOOLS = [{"function": {"name": n}} for n in ("service_overview", "metrics_overview", "error_signatures", "recent_deploys",
                                                            "slow_queries", "find_similar_incidents", "find_runbooks", "log_sample")]
ASK_TOOLS = [{"function": {"name": n}} for n in ("list_services", "list_incidents", "get_incident", "get_evidence", "similar_incidents", "search_runbooks",
                                                  "slow_queries", "get_timeline", "database_health")]


def test_it_says_what_it_is(fake):
    source = SCRIPT.read_text()
    assert source.splitlines()[1].startswith('"""DEMO STAND-IN, NOT A REAL MODEL') and "DEMO STAND-IN" in fake.BANNER
    assert "Ask PagerLens" in source or "ask:" in source                                   # the module doc says what Ask mode is
    out = fake.chat_reply({"messages": [{"role": "user", "content": "What is the meaning of life?"}], "tools": ASK_TOOLS})
    assert "DEMO STAND-IN" in out["content"] and "only knows three questions" in out["content"]


def test_the_investigation_path_is_unchanged(fake):
    brief = {"role": "user", "content": "Incident #1\nAlerting service: checkout-api\nSymptom: errors"}
    first = fake.chat_reply({"messages": [{"role": "system", "content": "s"}, brief], "tools": INVESTIGATION_TOOLS})
    assert [c["function"]["name"] for c in first["tool_calls"]] == list(fake.TOOLS_FIRST)
    assert all(json.loads(c["function"]["arguments"]) == {"service": "checkout-api"} for c in first["tool_calls"])
    tool = {"role": "tool", "tool_call_id": "call_1", "content": '<untrusted_data>\n{"observation_id": 7, "deploys": [{"version": "v2"}]}\n</untrusted_data>'}
    final = fake.chat_reply({"messages": [brief, tool], "tools": INVESTIGATION_TOOLS})
    answer = json.loads(final["content"])
    assert answer["hypotheses"][0]["category"] == "bad_deploy" and answer["hypotheses"][0]["supports"] == [7]
    assert fake.chat_reply({"messages": [{"role": "user", "content": "Reply with the single word OK."}]})["content"] == "OK"


def test_ask_mode_is_chosen_only_when_the_ask_tools_are_offered(fake):
    q = {"role": "user", "content": "Why is checkout-api failing?"}
    ask = fake.chat_reply({"messages": [q], "tools": ASK_TOOLS})
    assert ask["tool_calls"][0]["function"]["name"] == "list_incidents"
    assert json.loads(ask["tool_calls"][0]["function"]["arguments"])["service"] == "checkout-api"
    plain = fake.chat_reply({"messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "Alerting service: x"}], "tools": INVESTIGATION_TOOLS})
    assert plain["tool_calls"][0]["function"]["name"] == "service_overview"


def test_ask_answers_are_built_only_from_tool_results_and_cite_only_what_they_returned(fake):
    q = {"role": "user", "content": "Why is checkout-api failing?"}
    calls = [{"id": "c1", "type": "function", "function": {"name": "list_incidents", "arguments": "{}"}}]
    listing = {"incidents": [{"cite": "[incident #5]", "id": 5, "status": "open", "service": "checkout-api"}]}
    fenced = lambda obj: "<untrusted_data>\n" + json.dumps(obj) + "\n</untrusted_data>"          # noqa: E731
    step = fake.chat_reply({"messages": [q, {"role": "assistant", "tool_calls": calls}, {"role": "tool", "tool_call_id": "c1", "content": fenced(listing)}],
                            "tools": ASK_TOOLS})
    assert step["tool_calls"][0]["function"]["name"] == "get_incident" and json.loads(step["tool_calls"][0]["function"]["arguments"]) == {"incident_id": 5}
    # an incident that was never investigated: no invented cause
    calls2 = calls + [{"id": "c2", "type": "function", "function": {"name": "get_incident", "arguments": "{}"}}]
    bare = {"cite": "[incident #5]", "id": 5, "service": "checkout-api", "hypotheses": []}
    done = fake.chat_reply({"messages": [q, {"role": "assistant", "tool_calls": calls[:1]}, {"role": "tool", "tool_call_id": "c1", "content": fenced(listing)},
                                         {"role": "assistant", "tool_calls": calls2[1:]}, {"role": "tool", "tool_call_id": "c2", "content": fenced(bare)}],
                            "tools": ASK_TOOLS})
    assert "has not been investigated yet" in done["content"] and "[incident #5]" in done["content"] and "[evidence" not in done["content"]
    assert "DEMO STAND-IN" in done["content"]
