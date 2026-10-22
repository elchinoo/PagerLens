<p align="center"><img src="src/pagerlens/static/logo.svg" alt="PagerLens logo" width="96" height="96"></p>

<h1 align="center">PagerLens</h1>

An **incident-investigation agent** on **Postgres + pgvector**, with a web app, a REST API and an **MCP server**, built on [agentpg-kit](https://github.com/elchinoo/agentpg-kit) with optional single sign-on through the ecosystem [identity provider](https://github.com/elchinoo/identity). When an alert fires, PagerLens gathers read-only evidence (deploys, metrics, error logs, dependencies), ranks the possible causes with the evidence that supports or refutes each one, suggests runbook steps, and **learns from the causes people confirm**. It never changes your systems.

It ships with a **self-contained demo**: a fictional five-service online shop that breaks on demand, so everyone can try it without connecting anything. The same ingest API accepts your own logs, metrics, deploys and alerts.

> [!WARNING]
> **Hosted sandboxes can pause themselves and then answer `503`.**
> If you deploy PagerLens on a platform whose free tier auto-pauses idle workloads (AgentPG sandboxes do), the app stops after a period of inactivity and the platform returns an empty **HTTP 503** for every URL until you resume it. Your data is safe (it lives in the database), but the app is unreachable.
>
> - **Resume it:** `agentpg sandbox resume <sandbox-id>`.
> - **Then unlock it:** a restart locks stored provider keys until you sign in again (see [How secrets are handled](#how-secrets-are-handled)).
> - **Plan for it:** resume a few minutes before any demo.
> - **Details and fixes:** see [Troubleshooting](#troubleshooting) and [Deploy on AgentPG](#deploy-on-agentpg).

## What you get

- **Lab:** nine scripted failures (bad release, database pool exhaustion, memory leak, dependency outage, traffic spike, expired certificate, and three deliberately confusing mixes). The simulator writes realistic telemetry through the same ingest path real services use, fires the alert, and keeps the true cause hidden.
- **Investigation:** a bounded, read-only run that records every step. Each hypothesis cites observations that *support* or *refute* it, and you can open the raw data behind any claim. Red herrings (an unrelated deploy, a downstream victim) are checked and called out.
- **Three methods:** *Rules* (deterministic, free), *AI* (a model drives the same read-only tools) and *Rules + AI* (both, reconciled: agreement is rewarded, disagreement is shown, and anything the model says is checked against real evidence before it counts).
- **Collection:** push API, OpenTelemetry (OTLP/HTTP) and a pull agent with health probes and Prometheus scraping. See [How data gets in](#how-data-gets-in).
- **Memory:** mark the real cause and the incident is embedded in pgvector. Similar future incidents recall it as a prior. `pagerlens eval` measures a cold run against a warm one with the hidden answers.
- **Runbooks:** retrieved with hybrid vector + full-text search (reciprocal rank fusion) and attached to the report as *manual* next steps.
- **MCP server** at `/mcp` for Claude Code, VS Code, Codex, Cursor and more: ask "why is checkout failing?" from your editor.
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
3. **Hypotheses:** twelve failure patterns are scored from the evidence (bad deploy, database saturation, resource exhaustion, dependency outage, traffic spike, expired certificate, service down, sandbox paused, database unreachable, and for sensor fleets and collection pipelines such as [CityPulse](https://github.com/elchinoo/CityPulse): ingest overload, sensor-fleet outage, bad sensor data). Shares like `offline_pct` or `overloaded_pct` are judged on their own, since 40% of sensors offline needs no baseline to be alarming. For on/off health signals only the most recent samples count, so a fresh outage is not averaged away, and a newly monitored service with no history can still be diagnosed. A dependency that is itself failing is blamed rather than the alerting service. A deploy is only blamed if the new error appeared *after* it.
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

`pagerlens eval` replays all nine scenarios cold (no memory), teaches the memory the true causes, then replays them with different noise and reports top-1 and top-3 accuracy. For the **rules** method on a clean database it currently reports top-3 of 100% in both passes, and one scenario (a release that introduces a memory leak) misses at rank 1 until memory has seen a similar case.

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

## How secrets are handled

Files full of credentials are the usual way these tools leak, so PagerLens avoids them:

| Secret | Where it lives | How it is protected |
|---|---|---|
| **Admin password** | Entered once in the browser (first run needs the setup code from the server log) | Stored only as a salted **scrypt** hash. |
| **Browser session** | An `HttpOnly`, `SameSite=Strict` cookie (`Secure` over HTTPS) | Random value, only its SHA-256 stored server-side, 12-hour expiry. State-changing browser requests also need a custom header. |
| **API tokens** | Created in **Settings**, shown **once** | Only a SHA-256 hash is stored. Revocable. Scopes: `read` (list and read), `ingest` (push telemetry, read nothing, no MCP), `metrics` (scrape `/metrics` only) and `full`. See [Single sign-on and roles](#single-sign-on-and-roles-the-ecosystem-identity-provider) for what each can do. |
| **Provider API keys** (for the AI methods) | Entered in **Settings** | Encrypted (Fernet) with a random data key that your admin password wraps. The database alone reveals nothing; never returned by the API or logged. |

After a **restart** stored provider keys are locked until you sign in. `pagerlens reset-admin` is the only recovery from a lost password and it deletes the stored keys. See [SECURITY.md](SECURITY.md) for the full model and its limits.

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
`incidents:investigate`, `incidents:write` (notes, resolve, root cause), `simulator:run`, `ingest:write`, `metrics:scrape`,
`settings:manage` (accounts, tokens, vault, admin password) and `mcp:use`. A note added by a signed-in person carries their name.

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
| `PAGERLENS_API_KEY` | none | Optional static full-access credential for automation (file alternative: `/etc/pagerlens/api_key`). Prefer API tokens. |
| `PAGERLENS_ALLOW_ANONYMOUS` | `false` | `true` disables authentication entirely. Throwaway local demos only. |
| `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_CHAT_MODEL`, `EMBEDDING_MODEL`, `EMBEDDING_DIM` | none | Optional environment provider: embeddings for retrieval, and the `env` chat account for the AI methods. The schema is created for `EMBEDDING_DIM` (default 768) on first start, so set it before the first run. Without a provider a built-in offline hashing embedder is used: it matches words, not meaning. |

Retrieval embeddings are configured from the environment only in this version; the Settings page manages the chat provider accounts used by the AI methods. The same variables (`LLM_BASE_URL`, `LLM_API_KEY`, `LLM_CHAT_MODEL`) also define the `env` account.

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

Run `pagerlens reset-admin` where the server can reach the database (on AgentPG: `agentpg sandbox console <sandbox-id>`). It clears the password, the vault and every stored provider key, then restarts the first-run setup.

### What survives a pause

Everything: services, telemetry, incidents, runs, reports, memory, tokens and sessions live in Postgres. Only the app process restarts.

### `/readyz` returns 503 with `waking-database`

This comes from PagerLens itself, unlike the platform 503 above: the app is running but cannot reach the database yet, for example while a scaled-to-zero database wakes. Wait a few seconds and retry.

## Tests

```bash
make lint && make test            # unit tests, no database needed
set -a; . ./.env; set +a; make test-db   # adds the database tests against a throwaway database
```

## Security

See [SECURITY.md](SECURITY.md) for the model and to report a vulnerability privately.

## Design notes

- One small FastAPI service, plain-SQL migrations, no ORM, no queue: runs are synchronous and bounded.
- The investigator only runs registered read-only tools with capped output; log text is stored and shown as data and never used as an instruction. Ground truth for simulated incidents lives in a table the investigation code never reads (a test enforces that).
- Roadmap: live-provider evaluation numbers, provider-specific alert parsers, a scheduled collector for real platforms, and long-term telemetry storage.

## License

Apache-2.0. See [LICENSE](LICENSE).
