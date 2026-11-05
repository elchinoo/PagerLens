<p align="center"><img src="src/pagerlens/static/logo.svg" alt="PagerLens logo" width="96" height="96"></p>

<h1 align="center">PagerLens</h1>

An **incident-investigation agent** on **Postgres + pgvector**, with a web app, a REST API and an **MCP server**, built on [agentpg-kit](https://github.com/elchinoo/agentpg-kit) with optional single sign-on through the ecosystem [identity provider](https://github.com/elchinoo/identity). When an alert fires, PagerLens gathers read-only evidence (deploys, metrics, error logs, dependencies), ranks the possible causes with the evidence that supports or refutes each one, suggests runbook steps, and **learns from the causes people confirm**. It never changes your systems.

It ships with a **self-contained demo**: a fictional five-service online shop that breaks on demand, so everyone can try it without connecting anything. The same ingest API accepts your own logs, metrics, deploys and alerts.

**Documentation:** the complete [PagerLens guide](docs/GUIDE.md) (ecosystem integration, architecture, install, configuration, operations) and the [tutorial video script](docs/VIDEO-SCRIPT.md).

> [!WARNING]
> **Hosted sandboxes can pause themselves and then answer `503`.**
> If you deploy PagerLens on a platform whose free tier auto-pauses idle workloads (AgentPG sandboxes do), the app stops after a period of inactivity and the platform returns an empty **HTTP 503** for every URL until you resume it. Your data is safe (it lives in the database), but the app is unreachable.
>
> - **Resume it:** `agentpg sandbox resume <sandbox-id>`.
> - **Then unlock it:** a restart locks stored provider keys until you sign in again (see [How secrets are handled](#how-secrets-are-handled)).
> - **Plan for it:** resume a few minutes before any demo.
> - **Details and fixes:** see [Troubleshooting](#troubleshooting) and [Deploy on AgentPG](#deploy-on-agentpg).

## What you get

- **Lab:** ten scripted failures (bad release, database pool exhaustion, memory leak, dependency outage, traffic spike, expired certificate, a slow-query regression, and three deliberately confusing mixes). The simulator writes realistic telemetry through the same ingest path real services use, fires the alert, and keeps the true cause hidden.
- **Investigation:** a bounded, read-only run that records every step. Each hypothesis cites observations that *support* or *refute* it, and you can open the raw data behind any claim. Red herrings (an unrelated deploy, a downstream victim) are checked and called out.
- **Three methods:** *Rules* (deterministic, free), *AI* (a model drives the same read-only tools) and *Rules + AI* (both, reconciled: agreement is rewarded, disagreement is shown, and anything the model says is checked against real evidence before it counts).
- **Collection:** push API, OpenTelemetry (OTLP/HTTP) and a pull agent with health probes and Prometheus scraping. See [How data gets in](#how-data-gets-in).
- **Memory:** mark the real cause and the incident is embedded in pgvector. Similar future incidents recall it as a prior. `pagerlens eval` measures a cold run against a warm one with the hidden answers.
- **Runbooks:** retrieved with hybrid vector + full-text search (reciprocal rank fusion) and attached to the report as *manual* next steps.
- **EDB and AgentPG features:** live incident pages through Postgres `tcn` notifications, a Database tab with EDB's query insights (`edb_stat_monitor`, `edb_pg_tuner`, `query_advisor`), a `slow_query` finding fed by the other apps' `db_insights_*` metrics, and database-enforced masking for read-only and AI access (`a1p_readonly` plus masked views). See [EDB and AgentPG capabilities used by this app](docs/GUIDE.md#edb-and-agentpg-capabilities-used-by-this-app).
- **Ask PagerLens:** a chat tab (and the MCP tool `ask`) that answers plain-English questions ("Why is checkout-api failing?", "Have we seen this before?", "What is slow in the database?") by running a model over read-only tools. The answer must cite `[incident #N]`, `[evidence #N]` or `[runbook #N]`, and the server verifies every citation against the database: verified sources show as chips, anything else is marked `UNVERIFIED`. Bounded (rounds, tool calls, tokens, time, rate), read-only on a READ ONLY connection, log text fenced as untrusted data. See [Ask PagerLens](docs/GUIDE.md#710-ask-pagerlens-conversational-diagnostics).
- **Tuning (propose and approve):** PagerLens proposes `CREATE INDEX` / `CREATE STATISTICS` for its own database from EDB's query advisor and writes advice for slow queries in monitored apps; an administrator approves or rejects; applying is **off by default** (`PAGERLENS_ALLOW_TUNING_APPLY=false`), runs only statements the strict allow-list parser accepts, one at a time with timeouts, is audited, and records an EXPLAIN before and after. PagerLens never changes a monitored system. See [Tuning](docs/GUIDE.md#711-tuning-propose-and-approve).
- **MCP server** at `/mcp` for Claude Code, VS Code, Codex, Cursor and more: ask "why is checkout failing?" from your editor, with the `ask` tool for verified answers. A recipe for connecting Claude Code to PagerLens **and** the fleet's databases (read-only, through `ecoctl mcp`) is in [the guide](docs/GUIDE.md#91-connect-claude-code-to-pagerlens-and-the-fleet-databases).
- **Not built, said plainly:** self-healing orchestration (AgentPG has no non-interactive way to restart or scale a sandbox, and PagerLens does not act on monitored systems). See [what is built and what is not](docs/GUIDE.md#17-chat-agents-tuning-and-self-healing-what-is-built-and-what-is-not).
- **Safe by default:** first-run setup code, hashed tokens with separate `read`, `ingest`, `metrics` and `full` scopes, optional single sign-on with roles, encrypted provider keys, PII scrubbing of every log line before it is stored, a strict CSP and a non-root container. See [SECURITY.md](SECURITY.md).

## Quick start

Requires Docker and Python 3.11+.

```bash
cp .env.example .env              # then set POSTGRES_PASSWORD; .env is git-ignored
docker compose up -d db
python3 -m venv .venv && .venv/bin/pip install -e ../agentpg-kit -e ".[dev]"   # the shared blocks sit next to this checkout (images install the published kit)
set -a; . ./.env; set +a
.venv/bin/pagerlens migrate
.venv/bin/pagerlens seed          # demo fleet, runbooks and a healthy baseline
.venv/bin/pagerlens serve         # http://localhost:8000
```

The first time the server starts it prints a **one-time setup code**. Open the app, enter the code and choose an admin password. Then:

1. Open **Lab** and press **Break it** on any scenario.
2. On the incident page press **Investigate**. Read the hypotheses and open the evidence links.
3. Add a chat account under **Settings** and try **Rules + AI**: compare the two verdicts and open the evidence each one cites.
4. Press **Mark resolved** with the real cause, break the same thing again and investigate: the memory shows up in the report.

Or run everything in containers: `docker compose up` serves the app on http://localhost:8001 (check the `api` log for the setup code).

## How the investigation works

1. **Triage:** an alert opens an incident, or joins an open one with the same fingerprint or a near-identical symptom (pgvector similarity).
2. **Evidence:** for the alerting service and everything it depends on: metrics compared to a baseline, grouped error signatures with first-seen times, and deploys shortly before the first anomaly. Every tool call is a capped `SELECT`, logged as a run step, and stored as an observation with a digest.
3. **Hypotheses:** thirteen failure patterns are scored from the evidence (bad deploy, database saturation, resource exhaustion, dependency outage, traffic spike, expired certificate, service down, sandbox paused, database unreachable, slow query, and for sensor fleets and collection pipelines such as [CityPulse](https://github.com/elchinoo/CityPulse): ingest overload, sensor-fleet outage, bad sensor data). Shares like `offline_pct` or `overloaded_pct` are judged on their own, since 40% of sensors offline needs no baseline to be alarming. For on/off health signals only the most recent samples count, so a fresh outage is not averaged away, and a newly monitored service with no history can still be diagnosed. A dependency that is itself failing is blamed rather than the alerting service. A deploy is only blamed if the new error appeared *after* it.
4. **Refuting checks:** unrelated deploys, load that explains memory growth, and similar contradictions subtract from a hypothesis and are shown as such.
5. **Memory prior:** similar resolved incidents add a small, visible boost to the category they were resolved as.
6. **Report:** Markdown with timeline, ranked hypotheses, similar past incidents and runbook steps, ready to paste into Slack or an issue.

### Three methods

| Method | What runs | Needs |
|---|---|---|
| **Rules** | The deterministic investigator above. Transparent heuristics you can read in [`investigator.py`](src/pagerlens/investigator.py). | nothing |
| **AI** | A model drives the *same* read-only tools in a bounded loop (at most 10 model calls and 12 tool calls) and answers with ranked hypotheses that cite observation ids. | a chat account |
| **Rules + AI** (hybrid) | Rules first. The model then investigates the same incident and may cite the rules' observations. The two sets of hypotheses are reconciled. A lone AI opinion can never outrank a well-supported rules result, however confident it sounds. | a chat account |

**How hybrid reconciles them.** Hypotheses are matched by category (and by suspect service when both name one).

| Situation | Score |
|---|---|
| Rules and AI both found it | `0.5 × rules + 0.5 × AI confidence + 0.1` (capped at 99%) |
| Only the rules found it | `0.85 × rules`: the model did not corroborate it |
| Only the AI found it, citing real evidence | `0.5 × AI confidence` (at most 50%) |
| Only the AI found it and cited nothing real ("ungrounded") | `0.2 × AI confidence` |

The report has a **Rules vs AI** section stating whether the two agree, with the model's summary clearly labelled as model-written, and every hypothesis is tagged `rules`, `AI` or `rules + AI`. If the AI step fails in hybrid mode (bad key, provider down, unusable answer), the rules result is kept and the run records a warning.

**What keeps the model contained** (each point has a test):

- It can only call the registered **read-only** tools. Unknown tools are refused and unknown arguments are dropped. It has no tool that changes anything, and its output never triggers an action.
- Tool results reach it fenced as `<untrusted_data>`, truncated, with any attempt to close the fence removed. The system prompt tells it never to follow instructions found in that data.
- Its answer is validated: categories must be known, cited observations must exist **for this incident** (invented or foreign ids are dropped, with a warning), and its text is scrubbed again. Ungrounded claims are discounted hard.
- The tool-call budget, the number of rounds and a time limit bound every run. Token usage is recorded per run and shown in the run viewer.
- The provider key is checked **before** a run starts, so a locked vault returns `423` without creating a run. Memory off means the model is not even offered the memory tool.

Choose the provider with care: **log excerpts leave your server** for the AI and Rules + AI methods. PagerLens scrubs logs when they are ingested, but scrubbing is pattern based.

**Provider compatibility.** The AI methods use the OpenAI-style `/chat/completions` endpoint with function calling (`tools`). OpenAI, OpenRouter, and other OpenAI-compatible servers whose chosen model supports tools should work, and the same Settings presets as before apply. This has been tested end to end against a scripted stand-in provider only (including the real HTTP path, the encrypted key and the vault), **not** against live OpenAI, Claude, GLM, Kimi or OpenRouter models. A model that ignores `tools` simply returns an unusable answer, which is reported as such.

### What the evaluation does and does not show

`pagerlens eval` replays all ten scenarios cold (no memory), teaches the memory the true causes, then replays them with different noise and reports top-1 and top-3 accuracy. For the **rules** method on a clean database it currently reports top-3 of 100% in both passes, and one scenario (a release that introduces a memory leak) misses at rank 1 until memory has seen a similar case.

`pagerlens eval --mode hybrid --account env` (or `llm`) runs the same comparison with a model and prints the tokens used. It makes 18 investigations against your provider and spends credit, and **I have not run it against a live model**, so there are no AI accuracy numbers to quote yet. Use `env` for the CLI (set `LLM_BASE_URL`, `LLM_API_KEY` and `LLM_CHAT_MODEL`): accounts stored in the web app are locked outside the browser.

Read that honestly: the scenarios and the rules were written by the same people, the data is synthetic, and the warm pass replays scenario *shapes*, so it measures recall of similar past incidents rather than general skill. It is a regression test and a demonstration of the loop, not evidence about your production incidents. Running it resets the demo telemetry and removes the incidents it created.

## Send your own telemetry

Create an **Ingest** token under **Settings** (it can push data and read nothing), then:

```bash
export PAGERLENS_TOKEN=<ingest token>

curl -X POST https://<your-host>/api/ingest/logs \
  -H "Authorization: Bearer $PAGERLENS_TOKEN" -H "Content-Type: application/json" \
  -d '{"service":"checkout-api","events":[{"level":"error","message":"payment failed: timeout"}]}'

curl -X POST https://<your-host>/api/ingest/metrics -H "Authorization: Bearer $PAGERLENS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"service":"checkout-api","points":[{"name":"error_rate","value":0.4}]}'

curl -X POST https://<your-host>/api/ingest/deploys -H "Authorization: Bearer $PAGERLENS_TOKEN" \
  -H "Content-Type: application/json" -d '{"service":"checkout-api","version":"v2.14.0","author":"dev-a"}'

curl -X POST https://<your-host>/api/ingest/alerts -H "Authorization: Bearer $PAGERLENS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"service":"checkout-api","name":"HighErrorRate","summary":"5xx above 5%","severity":"sev2"}'

curl -X POST https://<your-host>/api/ingest/services -H "Authorization: Bearer $PAGERLENS_TOKEN" \
  -H "Content-Type: application/json" -d '{"name":"checkout-api","depends_on":["payments-gateway"]}'
```

- Metric names used by the investigator: `error_rate` (%), `latency_p95_ms`, `request_rate`, `cpu_pct`, `mem_pct`, `db_connections` (and `db_connections_max` for the pool size). Declare dependencies with `depends_on`; without them PagerLens cannot tell a victim from a cause.
- Up to 1000 events or points per request; timestamps may be up to 14 days old and 5 minutes ahead; bodies are capped at 2 MB.
- Every log line is **scrubbed before it is stored**: emails, IPv4/IPv6 addresses, card numbers, SSNs, phone numbers, bearer tokens, JWTs, API-key shapes and `password=`/`token=` values. Scrubbing is best effort and pattern based; do not rely on it as a licence to log secrets.
- Webhooks from Grafana, Alertmanager or similar tools can post to `/api/ingest/alerts` through a small relay; there is no provider-specific parser yet.
- `"investigate": true` in an alert body also runs a Rules investigation (no model, no cost) for a not-yet-investigated incident and returns its `run_id`; a failure there never loses the alert. The AI methods cannot be started from a webhook.

## How data gets in

| Path | Who sends it | Use it for |
|---|---|---|
| **Push API** (`/api/ingest/*`) | your own code, scripts, webhooks | logs, metrics, deploys, alerts, services |
| **OpenTelemetry (OTLP/HTTP)** (`/v1/logs`, `/v1/metrics`) | any OpenTelemetry SDK or Collector | apps you can instrument, with no PagerLens-specific code |
| **`pagerlens-agent`** (pull) | a small program you run anywhere | services that cannot push, black-box health, Prometheus `/metrics`, sandbox status |

All three need an **Ingest** token, or a service token from the identity provider with the `pagerlens.ingest` scope (the agent also uses a **Metrics** token for each target it scrapes). Everything goes through the same validation and PII scrubbing. Apps that report their own telemetry need no access to your hosting platform.

### OpenTelemetry

Point any OTLP/HTTP exporter at PagerLens. For example with the Python SDK or the Collector's `otlphttp` exporter:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=https://<your-host>
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer $PAGERLENS_TOKEN"
export OTEL_SERVICE_NAME=checkout-api
export OTEL_RESOURCE_ATTRIBUTES="service.version=2.14.0,pagerlens.depends_on=payments-gateway,inventory-api"
```

- Accepted: protobuf or JSON, optionally gzip (decompression is bounded), logs and metrics. **Traces are acknowledged but not stored** in this version.
- `service.name` becomes the service. A change in `service.version` is recorded as a deploy; the first time a service is seen is only a baseline, so connecting a service never invents a deploy. `pagerlens.depends_on` declares dependencies.
- Metrics: gauges are stored as they are, monotonic cumulative sums become a per-second `<name>_rate`, and histograms become `<name>_p95`. Attributes are not kept, so series that differ only by attributes collapse into one. To feed the built-in rules, name metrics like the ones listed under [Send your own telemetry](#send-your-own-telemetry); the agent does this for you.

### The pull agent

`pagerlens-agent` reads a YAML file ([`agent.example.yaml`](agent.example.yaml)) and, every interval, for each target:

- **HTTP probes** (`up`, `error_rate`, `latency_p95_ms`). Every failure is also logged as an error line, so the investigator has evidence. After `after_failures` failures in a row it raises an alert and opens an incident.
- **Prometheus scraping** of `/metrics` with the `http-standard` preset: `request_rate`, `error_rate`, `latency_p95_ms`, `cpu_pct`, `mem_pct`, `db_up`, and a deploy whenever the `app_info` version changes.
- **AgentPG sandbox status** (experimental; needs the `agentpg` CLI logged in on that machine): detects an auto-paused sandbox and reports `SandboxNotRunning`.

```bash
pip install git+https://github.com/elchinoo/PagerLens   # not on PyPI; or from a checkout: pip install -e .
                                           # or run the container image with --entrypoint pagerlens-agent
export PAGERLENS_TOKEN=<ingest token>
pagerlens-agent once agent.yaml --dry-run  # one cycle, prints what would be sent
pagerlens-agent run agent.yaml
```

Instead of a hand-copied token the agent can get its own from the identity provider: register a `service` client allowed the scope `pagerlens.ingest` and set `PAGERLENS_AGENT_OIDC_ISSUER`, `PAGERLENS_AGENT_OIDC_CLIENT_ID` and `PAGERLENS_AGENT_OIDC_CLIENT_SECRET[_FILE]` (no `PAGERLENS_TOKEN` needed; a static token still wins when both are set). This covers what the agent pushes to PagerLens; the `token_env` of a scrape target (that app's own **Metrics** token) is unchanged.

Secrets are only ever read from the environment variables named in the config; URLs with embedded credentials are refused; redirects are not followed; a rejected token stops the agent with a clear message and without printing the token; unsent data is kept in a bounded in-memory buffer and retried. Run it on your laptop, a VM or CI. Putting it in a sandbox means passing the token with `--env`, which is not a secret store, so prefer a place where you control the environment.

### `/metrics`

PagerLens, TrustDesk and CityPulse expose Prometheus metrics at `/metrics` with the same names (`http_requests_total`, `http_request_duration_seconds`, `db_up`, `app_info`, `process_*`). The endpoint needs a **Metrics** token, which can read nothing else and is refused on `/mcp`.

## Keeping the dashboard clean

Stale services, forgotten incidents and alert storms are handled in four ways. None of them teaches the memory: an incident only becomes memory when a person confirms a cause. Everything below resolves with a note and **no cause**, so nothing is embedded or recalled from it.

**Retire a service.** `POST /api/services/{name}/retire` with `{"confirm": "<name>"}` (the exact name, typed; anything else is refused). It needs the `services:retire` permission, which only administrators and `full` tokens hold, and like every write it needs the CSRF header from a browser session. It deletes the service with its metric points, log events, deploys and dependency edges (other services that depended on it lose the edge), and resolves its open incidents as `service retired`. Those incidents stay as history under the service's name; they are not deleted and not remembered. The response counts what was removed. In the UI: **Retire service** on a service page, and on the dashboard card of a stale service, each asking you to type the name. **Telemetry that arrives later for a retired name simply creates the service again**, empty (retire it again if that was a mistake). The OTLP version baseline of the service is forgotten too, so its first new version is not reported as a deploy.

**Resolve many incidents.** `POST /api/incidents/bulk-resolve` (permission `incidents:write`, like a single resolve). Send `reason` (required), `confirm: true` (without it the request is refused and nothing changes) and either `ids` (the selected incidents) or `all_matching: true` with an optional `status` (`open` or `investigating`) and `service`, which resolves every unresolved incident matching that filter, not only the 50 on screen. Already resolved incidents are skipped. Each incident gets `bulk resolved: <reason>` as its resolution note and a note saying who did it. The incident list has the same filters (`GET /api/incidents?status=&service=`, which also returns `total`), a checkbox per incident and a **Resolve many incidents** panel with the confirmation.

**Auto-resolve recovered incidents.** A background pass runs every minute in every web process (one at a time across replicas; `PAGERLENS_HOUSEKEEPING=false` turns the thread off for a process). With `auto_resolve_minutes` set (default 30, `0` = off) it resolves an incident with the note `auto-resolved: recovered` when **all** of these hold:

- its status is `open`: an incident anyone has investigated is `investigating` and is left alone;
- nobody has touched it: no note, and no investigation run of any kind (there is no assignment feature in PagerLens; a note is how a person claims one);
- its alert has not re-fired: its newest alert (its detection, if it has none) is at least `auto_resolve_minutes` old;
- its service is healthy: it reported without a gap longer than 5 minutes across the whole last `auto_resolve_minutes`, and not one data point in that window was over a limit the dashboard uses (`up`, `db_up` or `sandbox_running` at 0, error rate, CPU, memory, fleet health, overload, offline, fault or reject shares). A service with no data, a service that only just came back, or one that went silent for a while never qualifies.

Every condition is checked again inside the update, so a note or an investigation added a moment earlier is never overridden. Anything not on this list (a custom alert about something the metrics do not show) resolves when the service looks healthy and the alert is quiet; if that is too eager for you, raise the minutes or turn it off.

**Stale services.** A service whose newest metric point is older than `stale_after_minutes` (default 60, `0` = off, otherwise at least 5) gets `stale: true` and a **stale** badge. If it would be shown as degraded (for instance because of an open incident nobody will ever close) it is reported as stale instead, so it leaves the "N degraded" headline and the degraded chip; its incidents still count in the open-incident total until they are resolved or the service is retired. A service that never reported is `unknown`, not stale.

Both numbers live in **Settings** and in `GET`/`PUT /api/settings/housekeeping` (`{"auto_resolve_minutes": 30, "stale_after_minutes": 60}`, either key optional, permission `settings:manage`). They apply immediately and are stored with the other instance settings.

## How secrets are handled

Files full of credentials are the usual way these tools leak, so PagerLens avoids them:

| Secret | Where it lives | How it is protected |
|---|---|---|
| **Admin password** | Entered once in the browser (first run needs the setup code from the server log) | Stored only as a salted **scrypt** hash. |
| **Browser session** | An `HttpOnly`, `SameSite=Strict` cookie (`Secure` over HTTPS) | Random value, only its SHA-256 stored server-side, 12-hour expiry. State-changing browser requests also need a custom header. |
| **API tokens** | Created in **Settings**, shown **once** | Only a SHA-256 hash is stored. Revocable. Scopes: `read` (list and read), `ingest` (push telemetry, read nothing, no MCP), `metrics` (scrape `/metrics` only) and `full`. See [Single sign-on and roles](#single-sign-on-and-roles-the-ecosystem-identity-provider) for what each can do. |
| **Provider API keys** (for the AI methods) | Entered in **Settings** | Encrypted (Fernet) with a random data key that your admin password wraps. The database alone reveals nothing; never returned by the API or logged. |

After a **restart** stored provider keys are locked until you sign in. `pagerlens reset-admin` is the only recovery from a lost password and it deletes the stored keys. See [SECURITY.md](SECURITY.md) for the full model and its limits.

### Sealed boot

Anything in an app's environment, config files or image is readable by whoever breaches the platform. With sealed boot you deploy PagerLens with **one** setting, `APGKIT_SEALED`: a blob encrypted (AES-256-GCM) under an operator passphrase that holds `DATABASE_URL`, the OIDC client secret, the API and LLM keys and anything else secret. Make it with `ecoctl seal` from agentpg-ecosystem. The app starts sealed: it answers `503` except on `/_seal/*`, `/healthz`, `/health` and `/livez`. The operator sends the passphrase (encrypted to a key that exists only in that process); the app then opens the blob, runs the migrations, unlocks the vault with the same passphrase and starts serving. While unsealed the secrets are read from the blob first, so nothing else needs to be set. Without `APGKIT_SEALED` nothing changes. When sealing is on, `PAGERLENS_ENCRYPTION_KEY` is ignored and the vault is created or opened with the passphrase. See the agentpg-kit guide, section 7.3.3.

### Row MACs

Encryption keeps a stolen database unreadable; it does not stop someone who can only **write** to it (stolen database credentials) from planting rows. So the rows that grant access or carry trust also carry a `mac`: an HMAC-SHA256 under a subkey of the vault data key (agentpg-kit `Vault.row_mac`), computed over the columns that decide authority. With sealed boot that key exists only in the process's memory, so a database write alone cannot produce a valid MAC. A row with a missing or wrong MAC is treated as if it were not there and is logged once, with the table and key only (never values; the counter `pagerlens_tampered_rows_total` counts them).

| Table | Signed columns | What a forged row would have done |
|---|---|---|
| `web_session`, `api_token` (agentpg-kit) | id or token hash, subject, name, email, roles, source, expiry; name, prefix, scope, revoked | planted an admin session or token, widened a scope, undone a revocation |
| `llm_account` | id, provider, base URL, encrypted key, chat and embedding model, embedding size | sent prompts and the stored provider key to an attacker host |
| `runbook` | id, title, category, service, body | put attacker-written "manual steps" in front of a responder or an AI assistant that cites runbooks |
| `app_setting` (only `embedding_account_id`) | key, value | pointed embeddings (all incident and runbook text) at another account |

Checking happens only while the vault is **unlocked** (always, with sealed boot). While it is locked (development, tests, no vault) nothing is checked and behaviour is unchanged; rows the app writes in that state carry no MAC. Writes by the app sign in the same transaction, updates re-sign only rows that verified before, and `pagerlens rotate-key` / `POST /api/vault/rotate` re-sign the rows that verified under the old key.

**Upgrading.** Existing accounts, the embedding choice and any runbook you added yourself carry no MAC, so they are ignored until you run `pagerlens adopt-rowmacs` once (it asks for the admin password; `PAGERLENS_ADMIN_PASSWORD` works for automation, it is never a command-line argument). It **trusts the database as it is at that moment**: run it only when you believe the database is untouched. Runbooks that ship with PagerLens are signed automatically after unlock, because their text is compared with the code, not trusted. Sessions and API tokens written before this release are signed by the same command, or users sign in again. After `pagerlens reset-admin` the old key is gone: run `adopt-rowmacs` after setting the new password.

**Limits.** A row MAC does not stop: (1) **replay** of an older authentic row, for example from a backup (a revoked-then-restored account, an earlier runbook text); (2) **deleting** rows (denial of service; planted unsigned rows can also crowd out genuine ones, which is why runbook search over-fetches); (3) anything in a **column that is not signed**: display names, last four characters of a key, timestamps, embeddings, incident and telemetry data, the other `app_setting` keys (housekeeping thresholds, bookkeeping), tuning proposals (applying one is off by default, needs a person's approval and re-checks an allow-list of statements) and the kit's vault wraps (protected by the kit's own checks); (4) an attacker who also holds the data key, which is the key the MAC is made from.

## AIDB mode (opt-in, preview)

[EDB AI Accelerator (AIDB)](https://www.enterprisedb.com/docs/aidb/latest/) puts pipelines, knowledge bases, agents and governance inside Postgres. PagerLens can use it in two independent ways. **Both are off by default and plain Postgres keeps working exactly as before** (every test of the default path is unchanged); nothing below is needed to run PagerLens.

| Switch | Values | What it changes |
|---|---|---|
| `PAGERLENS_RETRIEVAL_BACKEND` | `app` (default), `aidb` | Where runbook search and incident recall come from (agentpg-kit `apgkit.retrieval.select`). |
| the investigator method | `rules`, `llm`, `hybrid` (defaults, unchanged) plus `aidb` and `aidb_hybrid` | An AIDB agent investigates instead of the app-side loop. |

### Before and after

| | Default (`app`) | AIDB mode |
|---|---|---|
| Runbooks | pgvector column filled by this process (`runbook.embedding`), our hybrid vector + full-text fusion | A live AIDB pipeline over `runbook.kb_text` keeps a knowledge base current; retrieval is AIDB's hybrid search. Insert a runbook and it is searchable seconds later with no app code |
| Incident memory | `incident.embedding`, re-embedded by `remember_incident` | A live pipeline over `incident_memory` (symptom and error signatures of resolved incidents; a trigger keeps it in step with `incident`) |
| Embedding model and size | Whatever `EMBEDDING_DIM`/the active account says; a size change is a reconciliation job | The pipeline owns its model (default AIDB's local `bge-small-en-v1.5-f16`, 384 dimensions, no key); a size change cannot strand the vectors |
| The AI investigator | A bounded loop in `llm_agent.py` over registered Python tools | An AIDB agent whose tools are custom SQL over read-only **evidence views**, run under a purpose bound to a role that holds SELECT on those views and nothing else |
| "Never changes your systems" | The tools only SELECT (code) | Also a grant boundary: the purpose role can read six views, no table, and write nothing; Postgres refuses the rest and AIDB records the refusal |
| Citations | Observation ids, checked here | Evidence ids (`deploy:12`, `log:345`, `metric:...`), checked here against the views for the incident's window; each verified id becomes an observation of the run |

What stays in the application whichever way the switches are set: row MACs on runbooks (an AIDB hit is only a key: the row is read back and its MAC verified here), citation verification, scrubbing and `<untrusted_data>` fencing, the bounded budget, and every human decision.

### Setting it up (an operator step)

The runtime role stays unprivileged (`aidb_users` plus a few grants). Everything that needs more is done once by an operator:

```bash
# the application's own DATABASE_URL (role that owns the tables) plus an administrator's connection string for this ONE command:
export PAGERLENS_AIDB_ADMIN_DSN=...        # or omit it and type it at the hidden prompt; never stored, logged or put in compose/env files
export LLM_BASE_URL=https://llm-gateway.example/v1 LLM_CHAT_MODEL=chat-default LLM_API_KEY=...   # only for the agent (see limits)
pagerlens aidb-setup                       # asks for the admin password (PAGERLENS_ADMIN_PASSWORD for automation); idempotent
pagerlens aidb-status                      # pipelines, agent, purpose, denials, and whether the seals verify (exit 1 on a problem)
export PAGERLENS_RETRIEVAL_BACKEND=aidb    # then restart, or wait: a fallback is re-examined every minute
```

`aidb-setup` creates the pipelines `pl_runbook` and `pl_incident` (live), the purpose `pagerlens_investigator` (role `aidb_p_pagerlens_investigator`, SELECT on the `pl_ev_*` views), seven SQL tools, and, when a gateway is configured, the model `pl_chat` and the agent. It also grants the runtime role `aidb_users`, SELECT on the two knowledge-base tables, USAGE on the gateway credential, SELECT on the seal table and on the narrow governance view `pl_governance_decisions_v` (below), and turns telemetry on. It grants the runtime role **no** access to `aidb_otel.traces` (a grant from an earlier version is revoked). Run it again and it reports `unchanged` for every object. The app's migrations create the views (as the table owner); the seal table is created there too.

At runtime the app only **verifies and reports**. `/readyz` gets an `aidb` object (`off`, `unavailable`, `not-set-up`, `unverified`, `ready` or `tampered`, plus the backend in effect) and never turns an otherwise ready app unready. `GET /api/aidb/status` (read permission) shows the same; `GET /api/aidb/governance` (`settings:manage`) feeds the **AIDB mode** panel in Settings: what the purpose may read, the verification result, and the tool calls the purpose denied. They are read from `pl_governance_decisions_v`, a security-barrier view created by `aidb-setup` and owned by the administrator: it lists when, status, decision id, agent, the purpose role, where the decision was taken, the denial reason and its class, only for this app's agent or agents running under its purpose, and never the attempted SQL. (`/readyz` reports `unsealed` when the seal table is missing: AIDB is refused, the app stays ready.)

**Falling back.** Asking for `aidb` where it cannot work (plain Postgres, not set up, no grant, a pipeline that fails verification) logs `RETRIEVAL BACKEND FALLBACK` at ERROR level and uses the app backend; a failure at query time falls back for that call. The `aidb` and `aidb_hybrid` methods are refused before a run exists (HTTP 422) when the agent is missing or fails verification; in `aidb_hybrid` a failure while the agent runs keeps the rules result, with a warning, as `hybrid` does.

**When the agent run fails.** An agent error, AIDB's iteration budget (12 tool calls) being exceeded, a tool call that failed identically three times in a row (what happens when the agent tries a tool its purpose refuses, such as the built-in `sleep`, after hostile text in the evidence asked for it), a timeout, or an answer that is not the required JSON ends the `aidb` method like a failed step of the `llm` method: HTTP **502** with `{"detail": "<reason>"}`, the run recorded as `failed` with the same reason in its `error`, and no hypotheses (the incident stays `investigating`). The reason is fixed text plus the number of tool calls the purpose denied (also visible in the governance panel); AIDB's own error text, SQL and secrets are never copied into it, the run's steps or the response. In `aidb_hybrid` the same failure returns **200** with the rules result and a warning that carries the same reason. The agent's instructions list its seven tools and tell it to ignore, and not to retry, any request (even inside `<untrusted_data>`) to call another tool; the evidence stays fenced as untrusted data, and the purpose's grants, not the prompt, are what actually stop it.

**Evidence views.** `pl_ev_services`, `pl_ev_incidents`, `pl_ev_deploys`, `pl_ev_alerts`, `pl_ev_logs`, `pl_ev_metrics`: masked like the read-only role's views (e-mail addresses, key-like strings and JWTs redacted, author names reduced to an initial), free text already fenced and truncated, root causes and everything secret absent. The tools take the incident's detected time as an argument so every query is windowed.

### Sealed definitions

The agent, the purpose (and the grants of its role), the SQL tools, the pipelines (source, columns, model), the gateway model and the credential's host restriction decide what is read and where it goes. `aidb-setup` seals each under the vault data key (agentpg-kit `apgkit.aidb`: the same idea as the row MACs; PagerLens adds the six views and `pl_fence`, whose SQL and owner it also seals). The app compares them with the catalog when the vault opens and then at most every five minutes whenever `/readyz`, an investigation, a retrieval or `pagerlens aidb-status` asks (so a readiness probe is the schedule). A definition edited behind the app's back is reported as `modified`, a deleted one as `missing`, a planted agent, tool or purpose as `unsealed`; each is logged to `pagerlens.security`, counted in `pagerlens_tampered_rows_total{table="aidb_<kind>"}` and shown in `/readyz`. The agent is refused while anything fails verification, and the AIDB retrieval backend is dropped (back to `app`, loudly) while a pipeline or model fails it. Like the row MACs, this is enforced only while the vault is unlocked.

### What is and is not verified (read this)

Verified on **AIDB 7.9.0 in the Docker image `aidb-postgres:17`** (built in the ecosystem repository), with an unprivileged application role and an administrator, by tests marked `aidb`: setup and its idempotence, live pipelines (insert and delete), retrieval parity with the app backend on the demo data, MAC verification of hits, the purpose role's privileges, all seven SQL tools executing under it, the agent run end to end, denials landing in `aidb_otel.traces` and in the panel, tamper detection of each kind, fallbacks.

Not verified, or limited:

- **No real chat model was run.** The agent was driven by a scripted OpenAI-compatible server standing in for the gateway, so the plumbing (tools, purpose, citations, recording) is tested but how well a real model follows AIDB's simulated tool calling (AIDB prompts for a JSON tool call when the provider is `openai_completions`, which is what the gateway serves) is **not**. Expect to tune the instructions. AIDB also adds its own built-in `sleep` tool to every agent.
- **Not tried on an AgentPG-hosted instance**: at the time of writing the platform's login role lacks the AIDB grants. `aidb-setup` needs an administrator who can create roles, own the database, register models and belong to `aidb_governance`; a superuser has all of it.
- **Preview features** are not used: agent memory and the AIDB MCP endpoint stay off. The AIDB agent method itself is a preview of this app, labelled so in the UI.
- Token usage is metered by AIDB and the gateway, not recorded in the run.
- The default embedding model is downloaded from Hugging Face by the database server on first use. Its similarity scale differs from the app's, so incident similarities from the knowledge base are rescaled (`PAGERLENS_AIDB_SIM_FLOOR`, default 0.5: cosine 0.5 maps to 0, 1 to 1) to keep the app's thresholds meaningful; this was calibrated on a handful of demo incidents, not on real history.
- Seals **detect, they do not prevent**: a superuser (or the owner of the `aidb` objects) can still change anything, the check runs only when it is run, and a copy of an older authentic definition can be replayed. Not sealed: the pipeline's distance operator (agentpg-kit's seal covers source, columns, steps and model), the grant that lets the runtime role use the gateway credential, the runtime role's memberships, `aidb.otel_client` and other server settings, row-level security, pipeline `Live` state, conversation history and the content of the source tables. The credential's secret cannot be sealed (AIDB never returns it).
- A purpose confines SQL tools. It does not confine MCP-imported tools or `aidb.run_tool`, which is why the agent has neither.
- Conversations are stored by AIDB in the database (`aidb.conversations`) and contain the fenced evidence the tools returned; `aidb_otel.traces` holds the SQL text of every recorded call and stays out of the runtime role's reach (the panel reads the narrow view). Anyone who can read `aidb.conversations` or the traces can read that evidence.

**Where this is going.** The Lab's simulator becomes AIDB's workload generator: sustained inserts into the source tables (pipeline lag and re-embedding under load), concurrent agent conversations, and retrieval latency as the incident history grows. That is not built yet.

## Single sign-on and roles (the ecosystem identity provider)

PagerLens can run **standalone** (the first-run setup code and an admin password, as above) or **federated** with the ecosystem's
[identity provider](https://github.com/elchinoo/identity). Register PagerLens there as a `web` app with client id `pagerlens`,
redirect URI `https://<pagerlens>/auth/callback`, and the roles below, then set:

| Variable | Meaning |
|---|---|
| `PAGERLENS_OIDC_ISSUER` | The identity provider's URL. Federation is off when unset. |
| `PAGERLENS_OIDC_CLIENT_ID` | Default `pagerlens`. |
| `PAGERLENS_OIDC_CLIENT_SECRET[_FILE]` | The app's secret from the provider. |
| `PAGERLENS_PUBLIC_URL` | The URL PagerLens is reached at (used to build the callback). |
| `PAGERLENS_LOCAL_LOGIN` | `false` removes the admin-password login when SSO is on (default keeps it as a break-glass). |
| `PAGERLENS_ENCRYPTION_KEY[_FILE]` | With SSO only (no admin password) this lets PagerLens create and unlock its vault for stored provider keys. |

| Role | May |
|---|---|
| `admin` | everything: provider accounts, API tokens, the Lab simulator (it replaces the demo telemetry), plus all of the below |
| `responder` | read everything (dashboard, incidents, evidence, runbooks), **investigate** (including the AI methods, which spend provider credit), add notes, **resolve incidents** and record the root cause, use MCP including its write tools |
| `viewer` | read the dashboard, incidents, evidence and runbooks; use MCP's read tools; cannot investigate, annotate or resolve |

Credentials that are not people map onto the same permissions through scopes. Local API tokens keep exactly the access they always had:

| Scope | Kind | Access |
|---|---|---|
| `read` | local API token | read dashboard, incidents, runbooks; MCP read tools |
| `ingest` | local API token | push telemetry (`/api/ingest/*`, OTLP) and nothing else; refused on `/mcp` |
| `metrics` | local API token | scrape `/metrics` and nothing else; refused on `/mcp` |
| `full` | local API token | everything an admin can do |
| `pagerlens.ingest` | identity-provider service scope | the same as an `ingest` token: what CityPulse, the CityPulse Simulator and `pagerlens-agent` use with `client_credentials` |
| `pagerlens.read` | identity-provider service scope | the same as a `read` token |
| `pagerlens.metrics` | identity-provider service scope | the same as a `metrics` token |

Behind the roles and scopes are these permissions (see `src/pagerlens/core.py`): `dashboard:read`, `incidents:read`, `runbooks:read`,
`incidents:investigate`, `incidents:write` (notes, resolve, bulk resolve, root cause), `services:retire` (admin only), `simulator:run`, `ingest:write`, `metrics:scrape`,
`settings:manage` (accounts, tokens, vault, admin password), `tuning:manage` (tuning proposals, administrators only) and `mcp:use`. A note added by a signed-in person carries their name.

## Using the MCP server

PagerLens serves [MCP](https://modelcontextprotocol.io) over streamable HTTP at `https://<your-host>/mcp`, authenticated with `Authorization: Bearer <token>`. Create a **read-only** token under **Settings > API tokens**; use a **full** token only if the assistant should run investigations and record root causes. With single sign-on, a person's access token works too: the `viewer` role reads, `responder` and `admin` can also use the write tools. `ingest` and `metrics` credentials and browser sessions are rejected on `/mcp`. Tools:

| Tool | Needs | Purpose |
|---|---|---|
| `list_services()` | read | Services with owner, tier, dependencies and open incident counts |
| `list_incidents(status?, limit?)` | read | Recent incidents |
| `get_incident(incident_id)` | read | Alerts, ranked hypotheses with evidence, and the latest report |
| `get_timeline(incident_id)` | read | The report's timeline |
| `similar_incidents(text, limit?)` | read | Resolved incidents that look similar, with how they were resolved |
| `search_runbooks(query, limit?)` | read | Hybrid search over runbooks |
| `ask(question, conversation_id?)` | read | Answer a plain-English question with citations the server verified (needs a chat account on the server; spends its credit; rate limited; read-only) |
| `investigate(incident_id, use_memory?, mode?, account?)` | **full** or responder | Run a bounded, read-only investigation. `mode` is `rules` (default), `llm` or `hybrid`; the AI modes need `account` (a chat account id, or `env`) and spend that provider's credit |
| `add_note(incident_id, note)` | **full** or responder | Attach a note |
| `mark_root_cause(incident_id, category, note?)` | **full** or responder | Record the confirmed cause; the incident becomes memory |

Write tools re-check the caller's own credential (`incidents:investigate` or `incidents:write`), so a read-only token or a viewer can never write even if a client offers the tool.

Set the token in the environment where the client runs, then add the server to your client. The same snippets, with your URL filled in, are on the app's **Connect** tab. Replace `<your-host>` below; for a local server use `http://localhost:8000/mcp`.

```bash
export PAGERLENS_TOKEN=<your token>
```

<details>
<summary><b>Claude Code</b></summary>

Run in a terminal:

```bash
claude mcp add --transport http pagerlens https://<your-host>/mcp \
  --header "Authorization: Bearer $PAGERLENS_TOKEN"
```

</details>

<details>
<summary><b>VS Code (GitHub Copilot)</b></summary>

Save as .vscode/mcp.json in your workspace (VS Code asks for the key once and stores it securely):

```json
{
  "servers": {
    "pagerlens": {
      "type": "http",
      "url": "https://<your-host>/mcp",
      "headers": {
        "Authorization": "Bearer ${input:pagerlens-key}"
      }
    }
  },
  "inputs": [
    {
      "type": "promptString",
      "id": "pagerlens-key",
      "description": "PagerLens API token",
      "password": true
    }
  ]
}
```

</details>

<details>
<summary><b>OpenCode</b></summary>

Add to opencode.json (project) or ~/.config/opencode/opencode.json:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "pagerlens": {
      "type": "remote",
      "url": "https://<your-host>/mcp",
      "enabled": true,
      "headers": {
        "Authorization": "Bearer {env:PAGERLENS_TOKEN}"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Codex CLI</b></summary>

Add to ~/.codex/config.toml:

```toml
[mcp_servers.pagerlens]
url = "https://<your-host>/mcp"
bearer_token_env_var = "PAGERLENS_TOKEN"
```

</details>

<details>
<summary><b>Cursor</b></summary>

Add to ~/.cursor/mcp.json (or .cursor/mcp.json in a project):

```json
{
  "mcpServers": {
    "pagerlens": {
      "url": "https://<your-host>/mcp",
      "headers": {
        "Authorization": "Bearer ${env:PAGERLENS_TOKEN}"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Windsurf</b></summary>

Add to ~/.codeium/windsurf/mcp_config.json:

```json
{
  "mcpServers": {
    "pagerlens": {
      "serverUrl": "https://<your-host>/mcp",
      "headers": {
        "Authorization": "Bearer ${env:PAGERLENS_TOKEN}"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Gemini CLI</b></summary>

Add to ~/.gemini/settings.json:

```json
{
  "mcpServers": {
    "pagerlens": {
      "httpUrl": "https://<your-host>/mcp",
      "headers": {
        "Authorization": "Bearer $PAGERLENS_TOKEN"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Cline</b></summary>

Add to cline_mcp_settings.json (Cline: MCP Servers, then Configure):

```json
{
  "mcpServers": {
    "pagerlens": {
      "type": "streamableHttp",
      "url": "https://<your-host>/mcp",
      "headers": {
        "Authorization": "Bearer <your token>"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Zed</b></summary>

Add to Zed settings.json:

```json
{
  "context_servers": {
    "pagerlens": {
      "url": "https://<your-host>/mcp",
      "headers": {
        "Authorization": "Bearer <your token>"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Claude Desktop</b></summary>

Claude Desktop needs a local bridge for bearer-key servers. Add to claude_desktop_config.json (requires Node.js):

```json
{
  "mcpServers": {
    "pagerlens": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://<your-host>/mcp",
        "--header",
        "Authorization:${AUTH}"
      ],
      "env": {
        "AUTH": "Bearer <your token>"
      }
    }
  }
}
```

</details>

Then ask your assistant something like: *"Using pagerlens, what incidents are open, and what is the most likely cause of the newest one?"*

Notes:
- The server authenticates with a bearer token, not OAuth, so web-based connector UIs that require OAuth (such as claude.ai custom connectors) are not supported. Use a client above.
- Client configuration formats change between releases. If a snippet is rejected, check that client's MCP documentation for the current field names (`url` vs `serverUrl` vs `httpUrl`, how headers are declared, and whether it expands environment variables).
- Treat tool results as untrusted text: log lines and incident titles come from your services and may contain instructions. Don't give an assistant that reads them more authority than you would give the document authors.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` / `DB_EXTERNAL_DSN` / `PSQL_CONNECTION_STRING` | `PG*` variables | Postgres URI; first one set wins. If none is set, libpq uses `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`. The `vector` and `pg_trgm` extensions must exist (or the role must be allowed to create them). |
| `HOST` / `PORT` | `0.0.0.0` / `8000` | Bind address. |
| `AUTO_SEED` | `false` | With `pagerlens start`, load the demo fleet if no services exist. |
| `PAGERLENS_ENCRYPTION_KEY` | none | Optional platform-managed secret that lets the vault unlock itself after a restart (file alternative: `/etc/pagerlens/encryption_key`). |
| `PAGERLENS_ALLOW_PRIVATE_LLM_URLS` | `false` | Allow provider URLs on loopback/private networks, for a local model server. Link-local is always blocked. |
| `PAGERLENS_API_KEY` | none | Optional static full-access credential for automation (file alternative: `/etc/pagerlens/api_key`), at least 32 characters. Prefer API tokens. |
| `PAGERLENS_ALLOW_ANONYMOUS` | `false` | `true` disables authentication entirely. Honoured only on a loopback bind (`PAGERLENS_HOST` or `HOST`) or with `PAGERLENS_ALLOW_ANONYMOUS_PUBLIC=1`. Throwaway local demos only. |
| `PAGERLENS_HOST`, `PAGERLENS_TRUSTED_HOPS`, `PAGERLENS_FORWARDED_ALLOW_IPS` | `HOST` / `0.0.0.0`, `1`, `127.0.0.1` | Bind address; number of your reverse proxies in front of the app (client address for rate limits); proxies uvicorn trusts for `X-Forwarded-*` (never `*`). |
| `PAGERLENS_HOUSEKEEPING` | `true` | `false` stops this process's background auto-resolve thread. The runtime switch is the `auto_resolve_minutes` setting (0 = off). |
| `PAGERLENS_RETRIEVAL_BACKEND` | `app` | `app` or `aidb`: where runbook search and incident recall come from ([AIDB mode](#aidb-mode-opt-in-preview)); `aidb` needs `pagerlens aidb-setup` and falls back to `app` loudly when it cannot work. |
| `PAGERLENS_AIDB_ADMIN_DSN` | none | Read **only** by `pagerlens aidb-setup` (an administrator's connection string; omit it to be prompted). Never put it in the app's environment, compose or env files. |
| `PAGERLENS_AIDB_SIM_FLOOR` | `0.5` | Cosine similarity that incident recall through AIDB treats as 0 (rescaling to the app's thresholds). |
| `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_CHAT_MODEL`, `EMBEDDING_MODEL`, `EMBEDDING_DIM` | none | Optional environment provider: embeddings for retrieval, and the `env` chat account for the AI methods. The vector columns are created for `EMBEDDING_DIM` (default 768) on first start; if you change it later, the next start resizes them and re-embeds (see below). Without a provider a built-in offline hashing embedder is used: it matches words, not meaning. |

**Changing `EMBEDDING_DIM` (or the model) on an existing database.** Stored vectors are derived data and cannot be converted between sizes. At startup, before anything else, PagerLens compares the size of `incident.embedding` and `runbook.embedding` with the configured one. If they differ it drops the two HNSW indexes, resizes the columns (`USING NULL`) and recreates the indexes in one transaction, then re-embeds every runbook (title + body) and incident (symptom, plus the stored error signatures once investigated or resolved) in batches. Notes:

- Startup never fails because of embeddings. If the provider is down, or the size cannot be applied, one line is logged, the rows keep a NULL embedding (runbook search falls back to full-text; incident recall returns nothing until they are filled) and the web app comes up. Missing embeddings are retried on every start.
- Sizes above 2000 cannot be indexed by pgvector (HNSW): the change is refused with a message and the old columns are kept.
- More than 5000 rows to embed: the columns are resized at startup and the re-embedding continues in a background thread.
- `pagerlens reembed` does the same on demand and re-embeds everything even if the size is unchanged (a new model with the same size); it probes the provider first and changes nothing if it fails. Admins also have `GET /api/embeddings/status` (configured vs stored size, rows without a vector, `needs_reembedding`, job progress) and `POST /api/embeddings/reembed`. There is no UI for this yet.
- The model and size the vectors were made with are recorded in the `embedding_index` setting.

Retrieval embeds with the environment provider by default. An administrator can instead choose a saved provider account (Settings > **Use for embeddings**, or `PUT /api/embeddings/active`); its embedding model and size are then used for runbook search, incident memory and alert de-duplication, and a different size than the stored vectors needs a re-embed (`POST /api/embeddings/reembed`). The same variables (`LLM_BASE_URL`, `LLM_API_KEY`, `LLM_CHAT_MODEL`) also define the `env` account.

## Container image

`.github/workflows/build-image.yml` lints, runs the unit and database tests (against a pgvector service), then publishes `ghcr.io/<owner>/<repo>` (`latest`, `sha-*`, version tags) from `main`, with a nightly rebuild for base-image updates.

The image runs `pagerlens start`: connect to the database (retrying while a scaled-to-zero database wakes), apply migrations, optionally seed, then serve. It runs as a non-root user.

## Deploy on AgentPG

> [!IMPORTANT]
> **Free-tier sandboxes auto-pause when idle and cannot be kept awake.** `agentpg sandbox status` shows `Auto-pause: true`. A paused sandbox answers **503** and does not wake on a request. The free tier allows only **one sandbox at a time**; on a plan that allows more you can run this beside TrustDesk. Read [Troubleshooting](#troubleshooting) before you rely on a deployment.

AgentPG sandboxes run any public image and can be linked to a Postgres instance, which injects the connection details (`PSQL_CONNECTION_STRING` and the `PG*` variables). PagerLens reads those automatically. **No key files are needed.**

**Use a dedicated instance.** PagerLens creates tables such as `app_setting` and `api_token` in the `public` schema and records its migrations by file name. TrustDesk does the same with some identical names, so two apps in one database would collide, and the second one's migrations could be skipped silently. A sandbox links to an *instance* (its primary database), so give each app its own instance. They run side by side on the free-tier-and-up plans that allow several instances and sandboxes.

```bash
agentpg login
agentpg create --name <instance-name> --size small           # a new instance just for PagerLens; note its id
agentpg extensions create vector <instance-id>              # may need elevated rights, so enable them here
agentpg extensions create pg_trgm <instance-id>

agentpg sandbox create pagerlens \
  --image ghcr.io/<owner>/pagerlens:latest \
  --instance <instance-id> --port 8000

agentpg sandbox status <sandbox-id>                         # prints the public HTTPS URL
agentpg sandbox logs <sandbox-id>                           # contains the one-time setup code
```

Then open the URL, enter the **setup code from the logs**, choose an admin password, and open the **Lab**. To preload the demo fleet automatically, create the sandbox with `--env AUTO_SEED=true`.

Notes:
- `--port 8000` is required: without it the platform replaces the image's command with an idle process.
- The image must be **public** on GHCR (package settings > change visibility).
- Setup is protected by the code in the logs. Complete it promptly: until then, anyone who finds the URL can try to guess the code (attempts are rate limited).
- After a resume, the stored provider keys are locked until you sign in.

## Troubleshooting

### I get a 503 on every page

**Cause:** the sandbox is paused, not broken. While paused, the platform's proxy returns an empty 503 for *every* path, including `/healthz` and the static files, before any request reaches PagerLens. Nothing expires on the app side.

```bash
agentpg sandbox status <sandbox-id>     # look for "Status: paused"
curl -i https://<your-host>/healthz     # a 503 with no content-security-policy header came from the platform, not the app
```

**Fix:** `agentpg sandbox resume <sandbox-id>`, reload the page and sign in. If you recreate or resume and the image looks stale, check that the sandbox pulled `:latest` (delete and recreate it if not).

### My MCP client says 401 but my token is right

Point the client at `/mcp` exactly as shown on the **Connect** tab. Make sure the token variable is exported in the shell that *starts the client* (`echo ${#PAGERLENS_TOKEN}` prints a number above 0), that it is not an `ingest` token, and that the sandbox is running the current image.

### I forgot the admin password

Run `pagerlens reset-admin` where the server can reach the database (on AgentPG: `agentpg sandbox console <sandbox-id>`). It clears the password, the vault and every stored provider key, then restarts the first-run setup. Row MACs were made under the old key, so run `pagerlens adopt-rowmacs` after setting the new password (see [Row MACs](#row-macs)).

### What survives a pause

Everything: services, telemetry, incidents, runs, reports, memory, tokens and sessions live in Postgres. Only the app process restarts.

### `/readyz` returns 503 with `waking-database`

This comes from PagerLens itself, unlike the platform 503 above: the app is running but cannot reach the database yet, for example while a scaled-to-zero database wakes. Wait a few seconds and retry.

## Tests

```bash
make lint && make test            # unit tests, no database needed
set -a; . ./.env; set +a; make test-db   # adds the database tests against a throwaway database
```

AIDB mode has its own tests. `tests/test_aidb_switches.py` runs on plain Postgres (it is part of the normal run: the switches, fallbacks, evidence views, citation checks and the agent's answer handling, with AIDB's calls scripted). `tests/test_aidb_runtime_role.py` (marker `aidb`, opt-in with `AIDB_TEST_URL`, needs docker and the image) starts its own container and runs verification, status, retrieval and the agent path as the runtime role with CREATE revoked on schema public, plus the missing-seal-table and tamper cases. `tests/test_aidb_integration.py` (marker `aidb`) needs a server with the extension and skips without `AIDB_TEST_URL`, which is what CI does (no AIDB image, no EDB token):

```bash
# image: see docker/aidb-postgres in the ecosystem repository (needs an EDB repository token as a BuildKit secret)
docker run -d --name aidb-test -p 127.0.0.1:55499:5432 -e POSTGRES_PASSWORD=... aidb-postgres:17 -c aidb.allow_insecure_egress=on
AIDB_TEST_URL=postgresql://postgres:...@127.0.0.1:55499/postgres AIDB_TEST_CALLBACK_HOST=192.168.65.254 .venv/bin/pytest -q -m aidb
```

`AIDB_TEST_CALLBACK_HOST` (an address of your machine the container can reach; Docker Desktop: `192.168.65.254`) enables the tests that run the agent against a scripted chat server. Each run creates its own database and roles and removes them.

## Security

See [SECURITY.md](SECURITY.md) for the model and to report a vulnerability privately.

## Design notes

- One small FastAPI service, plain-SQL migrations, no ORM, no queue: runs are synchronous and bounded.
- The investigator only runs registered read-only tools with capped output; log text is stored and shown as data and never used as an instruction. Ground truth for simulated incidents lives in a table the investigation code never reads (a test enforces that).
- Roadmap: live-provider evaluation numbers, provider-specific alert parsers, a scheduled collector for real platforms, and long-term telemetry storage.

## License

Apache-2.0. See [LICENSE](LICENSE).
