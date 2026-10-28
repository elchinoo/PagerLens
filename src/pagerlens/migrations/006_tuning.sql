-- Propose-and-approve tuning. PagerLens proposes changes to ITS OWN database (CREATE INDEX / CREATE STATISTICS on public tables,
-- from the kit's query advisor) and writes advice about monitored apps' slow queries; a person approves or rejects, and applying
-- is off unless PAGERLENS_ALLOW_TUNING_APPLY=true. Nothing here ever runs against another database.
CREATE TABLE tuning_proposal (
    id               bigserial PRIMARY KEY,
    source           text NOT NULL CHECK (source IN ('advisor', 'tuner', 'slow_query')),
    target           text NOT NULL DEFAULT 'self',          -- 'self' (PagerLens' own database) or the name of a monitored service (advice only)
    statement        text NOT NULL,                         -- the single SQL statement, or advice text where applicable is false
    applicable       boolean NOT NULL DEFAULT false,        -- true only when the statement passed the allow-list parser at creation
    rationale        text NOT NULL DEFAULT '',
    estimated_benefit text NOT NULL DEFAULT '',
    motivating_queryid text,                                -- the statement (query id) that motivated it, when known
    motivating_query text,                                  -- its normalised text ($1, $2 ...), cut by the kit at 300 characters
    status           text NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed', 'approved', 'rejected', 'applied', 'failed')),
    decided_by       text,
    decided_at       timestamptz,
    decision_note    text,
    applied_by       text,
    applied_at       timestamptz,
    before_timing    jsonb,
    after_timing     jsonb,
    error            text,
    created_at       timestamptz NOT NULL DEFAULT now()
);
-- one live proposal per statement; a rejected or applied one is not proposed again (checked in code), a failed one may be
CREATE UNIQUE INDEX tuning_proposal_live_statement ON tuning_proposal (statement) WHERE status IN ('proposed', 'approved');
CREATE INDEX tuning_proposal_status ON tuning_proposal (status, id DESC);

-- Every decision and every apply attempt, with who did it. Append-only by convention (the app never updates or deletes it).
CREATE TABLE tuning_audit (
    id          bigserial PRIMARY KEY,
    proposal_id bigint REFERENCES tuning_proposal(id) ON DELETE CASCADE,
    action      text NOT NULL,                              -- scan | created | approved | rejected | apply_refused | apply_started | applied | failed
    actor       text NOT NULL,
    detail      text NOT NULL DEFAULT '',
    at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tuning_audit_proposal ON tuning_audit (proposal_id, id);
