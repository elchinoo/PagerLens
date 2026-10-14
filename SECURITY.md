# Security policy

## Reporting a vulnerability
Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") on this repository. Include steps to reproduce and the
affected version or commit.

## Security model

**Credentials**
- First run: no credentials exist and every protected route is denied. The server prints a one-time setup code
  to its log; whoever presents it in the browser sets the admin password. The code is held in memory only and
  changes on each restart until setup is complete.
- The admin password is stored only as a salted scrypt hash (N=2^15, r=8, p=1), 12-character minimum.
- Browser sessions use a random cookie (`HttpOnly`, `SameSite=Strict`, `Secure` over HTTPS). Only its SHA-256
  is stored server-side. Sessions last 12 hours and all end when the password changes or you sign out. Browser
  writes also require a custom header, and no credential is kept in page storage.
- API tokens are random, shown once, stored as SHA-256 hashes, revocable, and have one of three scopes.
  `read` tokens can read incidents, reports and telemetry but cannot change data or manage accounts. `ingest`
  tokens can only push logs, metrics, deploys, services and alerts: they read nothing and are refused on `/mcp`.
  `full` tokens can do everything an admin session can.
- `/mcp` accepts `read` and `full` bearer tokens only, never browser cookies. The tools that change state
  (`investigate`, `add_note`, `mark_root_cause`) re-validate the caller's own token inside the tool, so a
  read-only token cannot write even through a client that offers the tool.
- An optional static `PAGERLENS_API_KEY` remains for automation. It is a full-access credential held in the
  environment or a file: treat it like a password, or leave it unset and use tokens.
- Failed sign-ins and bad credentials are rate limited (10 per minute per client address, in memory, per
  process). Behind a reverse proxy all clients can share one address, so add proxy-level limits too.
- With no credential configured the app **denies everything**. Anonymous access exists only behind the explicit
  opt-in `PAGERLENS_ALLOW_ANONYMOUS=true`; never use it on a reachable host.

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
- Provider accounts are stored for the planned LLM investigator; when it exists, log excerpts sent to a provider
  will leave your server, so choose a provider accordingly.

**Platform**
- The container runs as a non-root user. Secrets are never baked into the image or stored in the repository.
- Interactive API docs are disabled. The UI is served with a strict Content-Security-Policy (no inline script
  or style) and `X-Frame-Options: DENY`, `nosniff` and `no-referrer`.
- Run behind TLS. The app itself does not terminate TLS.
