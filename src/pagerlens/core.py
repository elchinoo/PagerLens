"""This app's instances of the shared blocks (agentpg-kit), and the authorization model of PagerLens.

Permissions are what the code checks (`incidents:investigate`); roles (given to people by the identity provider) and scopes
(given to services, local API tokens and the static key) are mapped onto them here, in one place.
"""

from apgkit import metrics as metrics_mod
from apgkit.auth import AppAuth, Authenticator, LocalAuth, from_env
from apgkit.config import env_bool
from apgkit.db import Database
from apgkit.llm import LLMClient
from apgkit.netguard import NetGuard
from apgkit.vault import Vault

from . import __version__

APP = "pagerlens"
COOKIE = "pl_session"
CSRF_HEADER = "x-pagerlens-csrf"

db = Database(vector=True)
vault = Vault("PAGERLENS")
netguard = NetGuard("PAGERLENS_ALLOW_PRIVATE_LLM_URLS")
llm = LLMClient(netguard, vault)
metrics = metrics_mod.Metrics(APP, __version__)

ALL = frozenset({"*"})
PERMISSIONS = {
    "dashboard:read": "see the dashboard, the monitored services, their health and statistics",
    "incidents:read": "read incidents, hypotheses, evidence, telemetry and the lab's scenario list",
    "runbooks:read": "read the runbooks",
    "incidents:investigate": "run an investigation (the AI modes spend provider credit)",
    "incidents:write": "add notes, resolve incidents and record the confirmed root cause",
    "simulator:run": "trigger or reset the lab simulator (replaces the telemetry of the demo fleet)",
    "ingest:write": "push telemetry: logs, metrics, deploys, services, alerts and OTLP",
    "metrics:scrape": "scrape /metrics",
    "settings:manage": "provider accounts, embeddings, API tokens, the vault and the admin password",
    "mcp:use": "use the MCP server (what it may do follows from the other permissions)",
}
READ = frozenset({"dashboard:read", "incidents:read", "runbooks:read", "mcp:use"})
ROLE_PERMISSIONS = {
    "admin": ALL,
    "responder": READ | {"incidents:investigate", "incidents:write"},
    "viewer": READ,
}
SCOPE_PERMISSIONS = {
    # local API tokens (the scopes that existed before single sign-on keep exactly the access they had)
    "read": READ, "ingest": frozenset({"ingest:write"}), "metrics": frozenset({"metrics:scrape"}), "full": ALL,
    # scopes the identity provider can grant to services
    "pagerlens.ingest": frozenset({"ingest:write"}), "pagerlens.read": READ, "pagerlens.metrics": frozenset({"metrics:scrape"}),
}
fed = from_env("PAGERLENS", APP)
APP_AUTH = AppAuth(APP, fed.client_id, ROLE_PERMISSIONS, SCOPE_PERMISSIONS)


def _on_reset(conn) -> None:
    conn.execute("UPDATE llm_account SET api_key_enc = NULL, api_key_last4 = NULL")


local = LocalAuth(APP_AUTH, env_prefix="PAGERLENS", token_prefix="pl_", token_scopes={"read", "ingest", "metrics", "full"}, vault=vault,
                  on_reset=_on_reset)
auth = Authenticator(APP_AUTH, local, db, cookie_name=COOKIE, verifier=fed.verifier,
                     allow_anonymous=lambda: env_bool("PAGERLENS_ALLOW_ANONYMOUS"))
public_url_env = "PAGERLENS_PUBLIC_URL"
