-- PagerLens schema: instance settings and auth, the telemetry fleet, incidents, agent runs and the knowledge base.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS app_setting (
    key   text PRIMARY KEY,
    value text NOT NULL
);

CREATE TABLE llm_account (
    id               bigserial PRIMARY KEY,
    name             text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 60),
    provider         text NOT NULL DEFAULT 'custom',
    base_url         text NOT NULL,
    api_key_enc      text,                      -- encrypted with the vault data key; never returned by the API
    api_key_last4    text,
    chat_model       text,
    embedding_model  text,
    embedding_dim    integer CHECK (embedding_dim IS NULL OR embedding_dim BETWEEN 8 AND 2000),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_token (
    id            bigserial PRIMARY KEY,
    name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 60),
    token_hash    text NOT NULL UNIQUE,         -- sha256 of the token; the token itself is shown once
    prefix        text NOT NULL,
    scope         text NOT NULL CHECK (scope IN ('read', 'ingest', 'full')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz
);

CREATE TABLE web_session (
    token_hash    text PRIMARY KEY,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);

-- Fleet and telemetry ------------------------------------------------------------------------
CREATE TABLE service (
    id           bigserial PRIMARY KEY,
    name         text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    owner        text,
    tier         text,
    description  text,
    depends_on   text[] NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE deploy (
    id           bigserial PRIMARY KEY,
    service_id   bigint NOT NULL REFERENCES service(id) ON DELETE CASCADE,
    version      text NOT NULL,
    git_sha      text,
    author       text,
    summary      text,
    deployed_at  timestamptz NOT NULL
);
CREATE INDEX deploy_service_time ON deploy (service_id, deployed_at DESC);

CREATE TABLE log_event (
    id           bigserial PRIMARY KEY,
    service_id   bigint NOT NULL REFERENCES service(id) ON DELETE CASCADE,
    ts           timestamptz NOT NULL,
    level        text NOT NULL,
    message      text NOT NULL,                 -- already scrubbed of PII/secrets at ingest
    fields       jsonb NOT NULL DEFAULT '{}',
    signature    text NOT NULL                  -- normalised message used to group similar errors
);
CREATE INDEX log_service_time ON log_event (service_id, ts DESC);
CREATE INDEX log_signature ON log_event (service_id, signature, ts);

CREATE TABLE metric_point (
    service_id   bigint NOT NULL REFERENCES service(id) ON DELETE CASCADE,
    name         text NOT NULL,
    ts           timestamptz NOT NULL,
    value        double precision NOT NULL,
    PRIMARY KEY (service_id, name, ts)
);

-- Incidents ------------------------------------------------------------------------------------
CREATE TABLE incident (
    id                   bigserial PRIMARY KEY,
    service_id           bigint NOT NULL REFERENCES service(id) ON DELETE CASCADE,
    title                text NOT NULL,
    status               text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved')),
    severity             text NOT NULL DEFAULT 'sev3',
    fingerprint          text NOT NULL,
    symptom              text NOT NULL,
    detected_at          timestamptz NOT NULL DEFAULT now(),
    resolved_at          timestamptz,
    root_cause_category  text,
    root_cause_note      text,
    embedding            vector({{EMBEDDING_DIM}}),   -- symptom + error signatures, used to recall similar incidents
    created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incident_status ON incident (status, detected_at DESC);
CREATE INDEX incident_embedding ON incident USING hnsw (embedding vector_cosine_ops);

CREATE TABLE alert (
    id           bigserial PRIMARY KEY,
    service_id   bigint REFERENCES service(id) ON DELETE SET NULL,
    incident_id  bigint REFERENCES incident(id) ON DELETE SET NULL,
    source       text NOT NULL,
    name         text NOT NULL,
    severity     text NOT NULL DEFAULT 'sev3',
    summary      text,
    labels       jsonb NOT NULL DEFAULT '{}',
    fired_at     timestamptz NOT NULL DEFAULT now()
);

-- Ground truth for SIMULATED incidents only. Investigations never read this table; it is used to
-- score evaluations and to let a person reveal the answer afterwards.
CREATE TABLE sim_truth (
    incident_id  bigint PRIMARY KEY REFERENCES incident(id) ON DELETE CASCADE,
    scenario     text NOT NULL,
    category     text NOT NULL
);

CREATE TABLE incident_note (
    id           bigserial PRIMARY KEY,
    incident_id  bigint NOT NULL REFERENCES incident(id) ON DELETE CASCADE,
    author       text NOT NULL DEFAULT 'operator',
    body         text NOT NULL CHECK (length(body) <= 4000),
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Agent runs, evidence and hypotheses ---------------------------------------------------------
CREATE TABLE run (
    id           bigserial PRIMARY KEY,
    incident_id  bigint NOT NULL REFERENCES incident(id) ON DELETE CASCADE,
    mode         text NOT NULL CHECK (mode IN ('rules', 'llm')),
    status       text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'done', 'failed')),
    use_memory   boolean NOT NULL DEFAULT true,
    account      text,
    error        text,
    budget       jsonb NOT NULL DEFAULT '{}',
    usage        jsonb NOT NULL DEFAULT '{}',
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz
);

CREATE TABLE run_step (
    id           bigserial PRIMARY KEY,
    run_id       bigint NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    ord          integer NOT NULL,
    kind         text NOT NULL,
    tool         text,
    args         jsonb NOT NULL DEFAULT '{}',
    summary      text NOT NULL,
    row_count    integer,
    ms           integer
);

CREATE TABLE observation (
    id           bigserial PRIMARY KEY,
    incident_id  bigint NOT NULL REFERENCES incident(id) ON DELETE CASCADE,
    run_id       bigint NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    step_id      bigint REFERENCES run_step(id) ON DELETE SET NULL,
    source       text NOT NULL,
    kind         text NOT NULL,
    summary      text NOT NULL,
    payload      jsonb NOT NULL,
    digest       text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hypothesis (
    id           bigserial PRIMARY KEY,
    incident_id  bigint NOT NULL REFERENCES incident(id) ON DELETE CASCADE,
    run_id       bigint NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    category     text NOT NULL,
    title        text NOT NULL,
    explanation  text NOT NULL,
    score        real NOT NULL,
    rank         integer NOT NULL,
    suspect      text                           -- the service the hypothesis points at
);

CREATE TABLE hypothesis_evidence (
    id              bigserial PRIMARY KEY,
    hypothesis_id   bigint NOT NULL REFERENCES hypothesis(id) ON DELETE CASCADE,
    observation_id  bigint NOT NULL REFERENCES observation(id) ON DELETE CASCADE,
    stance          text NOT NULL CHECK (stance IN ('supports', 'refutes')),
    note            text NOT NULL
);

CREATE TABLE report (
    id           bigserial PRIMARY KEY,
    incident_id  bigint NOT NULL REFERENCES incident(id) ON DELETE CASCADE,
    run_id       bigint NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    markdown     text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Knowledge base: runbooks (resolved incidents are recalled through incident.embedding) --------
CREATE TABLE runbook (
    id         bigserial PRIMARY KEY,
    title      text NOT NULL UNIQUE,
    category   text NOT NULL,
    service    text,
    body       text NOT NULL,
    tsv        tsvector GENERATED ALWAYS AS (to_tsvector('english', title || ' ' || body)) STORED,
    embedding  vector({{EMBEDDING_DIM}}),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX runbook_tsv ON runbook USING gin (tsv);
CREATE INDEX runbook_embedding ON runbook USING hnsw (embedding vector_cosine_ops);
