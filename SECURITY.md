# Security policy

## Reporting a vulnerability
Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") on this repository. Include steps to reproduce and the
affected version or commit.

## Security model

**Federated sign-in** (optional, `PAGERLENS_OIDC_ISSUER`)
- Access tokens are verified locally against the identity provider's JWKS (algorithm allow-list, issuer, audience, expiry), so
  a token minted for another app or signed by another key is refused. Only the roles of THIS app are honoured, and they are
  mapped to permissions in `core.py`; an authenticated person with no role here can do nothing.
- Browser sign-in is authorization code + PKCE with state and nonce; the session is server-side and carries the person's roles
  from the verified ID token. Sign-out also ends the single sign-on session. Role changes reach an existing session at its next sign-in.
- `/mcp` needs the `mcp:use` permission; ingest and metrics credentials are refused. The tools that change state check
  `incidents:investigate` or `incidents:write` again from the caller's own credential.
- Services use the scopes `pagerlens.ingest`, `pagerlens.read` and `pagerlens.metrics`, which carry the same access as a local
  `ingest`, `read` and `metrics` token. A service token with the ingest scope can push telemetry and read nothing.

**Credentials**
- First run: no credentials exist and every protected route is denied. The server prints a one-time setup code
  to its log; whoever presents it in the browser sets the admin password. The code is held in memory only and
  changes on each restart until setup is complete.
- The admin password is stored only as a salted scrypt hash (N=2^15, r=8, p=1), 12-character minimum.
- Browser sessions use a random cookie (`HttpOnly`, `SameSite=Strict`, `Secure` over HTTPS). Only its SHA-256
  is stored server-side. Sessions last 12 hours and all end when the password changes or you sign out. Browser
  writes also require a custom header, and no credential is kept in page storage.
- API tokens are random, shown once, stored as SHA-256 hashes, revocable, and have one of four scopes.
  `read` tokens can read incidents, reports and telemetry but cannot change data or manage accounts. `ingest`
  tokens can only push logs, metrics, deploys, services and alerts: they read nothing and are refused on `/mcp`.
  `metrics` tokens can only read `/metrics`: they read no incident data and are refused on `/mcp`.
  `full` tokens can do everything an admin session can.
- `/mcp` accepts bearer credentials that hold `mcp:use` (`read` and `full` tokens, and federated people or services allowed to),
  never browser cookies. The tools that change state (`investigate`, `add_note`, `mark_root_cause`) re-validate the caller's
  own credential inside the tool, so a read-only token cannot write even through a client that offers the tool.
- An optional static `PAGERLENS_API_KEY` remains for automation. It is a full-access credential held in the
  environment or a file: treat it like a password, or leave it unset and use tokens.
- Failed sign-ins and bad credentials are rate limited (10 per minute per client address, in memory, per
  process). Behind a reverse proxy all clients can share one address, so add proxy-level limits too.
- With no credential configured the app **denies everything**. Anonymous access exists only behind the explicit
  opt-in `PAGERLENS_ALLOW_ANONYMOUS=true`; never use it on a reachable host.

**Collection paths**
- `/v1/logs`, `/v1/metrics` and `/v1/traces` (OTLP/HTTP) need an `ingest` token and go through the same validation and
  scrubbing as the ingest API. Request bodies are capped at 2 MB and gzip bodies are inflated with a hard 8 MB limit
  (a decompression bomb is rejected with `400`). Unknown encodings and content types are refused.
- `/metrics` needs a `metrics` token and exposes route templates, never raw paths, so identifiers cannot leak into labels.
- `pagerlens-agent` reads secrets only from the environment variables its config names, refuses URLs with embedded
  credentials, never follows redirects, never prints a token, and sends each target its own token only to that target.
  The agent's `agentpg` collector runs the CLI with a validated sandbox id and no shell.

**Provider API keys**
- Encrypted at rest with Fernet using a random 256-bit data key. The data key is stored only *wrapped*
  (encrypted) under a key derived from the admin password, and optionally under a platform-managed secret
  (`PAGERLENS_ENCRYPTION_KEY`). A database dump alone reveals no provider key.
- After a restart the data key is not in memory: the vault is **locked** until the admin enters the password
  (or the platform secret unlocks it automatically if configured). While locked, features that need a stored key
  return HTTP 423.
- Keys are never returned by the API (only the last 4 characters), never logged, and removed from provider
  error messages before they are shown.
- Recovery from a lost password is `pagerlens reset-admin`, which deletes the password, the vault and every stored
  provider key. There is no back door.
- An attacker with **both** database access and a running, unlocked server process, or with the admin password,
  can use the keys. Use provider-side spending limits and revoke a key at the provider if you suspect exposure.

**Outbound requests (SSRF)**
- Provider base URLs entered in the UI are validated before every call: only `https` (plain `http` only for
  allowed local servers), no embedded credentials, and no loopback, private, link-local (cloud metadata) or
  carrier-grade-NAT addresses unless the operator sets `PAGERLENS_ALLOW_PRIVATE_LLM_URLS=true`. Link-local is
  always blocked. Redirects are never followed and responses are size-limited.
- Limitation: the host name is resolved once for the check and again by the HTTP client, so a hostile DNS
  server could answer differently the second time. Redirects are refused, which closes the usual route; run the
  server with network egress rules if that matters to you.

**Telemetry and content**
- Every ingested log line is scrubbed **before it is stored**: emails, IP addresses, card numbers, SSNs, phone
  numbers, bearer tokens, JWTs, API-key shapes and `password=`/`token=` values are replaced by placeholders, and
  messages are cut at 2,000 characters. Scrubbing is pattern based and best effort: it will miss secrets in
  unusual formats, so do not log credentials in the first place.
- Ingest is validated and bounded: service and metric names are restricted, batches are limited to 1,000 items,
  timestamps must fall within 14 days back and 5 minutes ahead, and request bodies are capped at 2 MB.
- Log text, incident titles and deploy summaries are **untrusted data**. The investigator never interprets them
  as instructions: it runs a fixed set of read-only tools with capped output, and a test covers a log line that
  tries to steer it. Anything shown to an assistant over MCP should be treated the same way.
- Investigations only `SELECT` from monitored-data tables; their writes go to PagerLens' own run, observation,
  hypothesis and report tables. PagerLens has no tool that changes a monitored system, and recommended actions are
  text for a person to carry out.
- Simulated incidents keep their true cause in a separate table that the investigation code never reads.
- The data is single-tenant: anyone with `read` access sees every service, log line and incident.
- **AI investigations.** The AI and Rules + AI methods send incident context and log excerpts to the chat provider
  you choose, using a stored key that is checked before the run starts. The model can only call the registered
  read-only tools (unknown tools are refused, unknown arguments dropped), sees tool results fenced as untrusted
  data, and is bounded by tool-call, round and time limits. Its answer is validated before use: unknown categories
  become `unknown`, citations of observations that do not exist for the incident are dropped, ungrounded
  hypotheses are heavily discounted, and its text is scrubbed again. It has no tool that changes any system and
  its output never triggers an action. A model can still be misled by hostile log text into a wrong *opinion*; the
  protection is that opinions need real cited evidence, are shown next to the rules' verdict, and a human decides.
  Model-written text in reports is labelled as such.
- **Ask PagerLens** (`POST /api/ask`, the `ask` MCP tool). Same model-safety properties as above, plus: the turn runs on a
  database connection opened READ ONLY; the model is offered nine read-only tools; every citation in its answer is checked
  against the database (the record must exist and have been read through a tool in that conversation) and a failing one is
  marked `UNVERIFIED` (harmless variants such as `[#95]` are accepted only for records that were read; a fabricated
  id, or a tool name in brackets, never verifies); the first round requires a tool call and an uncited or failing answer
  gets one corrective round inside the same bounds, after which it is shown as Unverified; questions are rate limited per caller and overall; conversations are kept in memory only, scrubbed,
  bounded and bound to the credential that started them. What a tool returns is sent to the chat provider. Verification
  proves a record exists and was read, not that it supports the claim.
- **Tuning.** `tuning:manage` (administrators and `full` tokens) guards the proposals, their approval and the apply. Apply
  is off unless `PAGERLENS_ALLOW_TUNING_APPLY=true`, changes only PagerLens' own database, only after an approval, only
  through a strict allow-list parser (`CREATE INDEX` / `CREATE STATISTICS` on `public` tables; what runs is rebuilt from
  the parsed pieces), one statement at a time with a statement and a lock timeout, and every step is written to
  `tuning_audit`. It never changes a monitored system or a server setting.
- Only a `full` token, an admin session or a federated `responder`/`admin` (permission `incidents:investigate`) can start an AI investigation, because it spends provider credit. Responders see the id, name and chat model of the accounts they may use, never base URLs or keys.

**Platform**
- The container runs as a non-root user. Secrets are never baked into the image or stored in the repository.
- Interactive API docs are disabled. The UI is served with a strict Content-Security-Policy (no inline script
  or style) and `X-Frame-Options: DENY`, `nosniff` and `no-referrer`.
- Run behind TLS. The app itself does not terminate TLS.
