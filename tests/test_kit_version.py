"""The EDB / AgentPG capability work (database insights, masking helpers, migrate hooks) needs agentpg-kit 0.3.1 or newer (masking.reassert_forever, deny_tables)."""
import apgkit


def _version(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split(".")[:3])


def test_installed_kit_is_at_least_0_3_1():
    assert _version(apgkit.__version__) >= (0, 3, 1), apgkit.__version__


def test_kit_exposes_what_this_app_uses():
    from apgkit import insights, masking, migrate
    from apgkit.metrics import Metrics
    assert callable(insights.insights_payload) and callable(masking.mask_view) and callable(masking.reassert_forever) and callable(masking.deny_tables) and callable(Metrics.add_insights_collector)
    assert "after_migrate" in migrate.run.__code__.co_varnames or "after_migrate" in migrate.run.__kwdefaults__
