-- AIDB mode (opt-in, see README "AIDB mode"). Everything here is plain Postgres and harmless without AIDB: it gives AIDB pipelines
-- a text column to read, keeps resolved-incident text in one table, lets runs record the new investigator methods, and creates the
-- table the seals of AIDB definitions live in (the same table agentpg-kit's `apgkit.aidb` uses).

-- Runbooks: one text column (title and body) that an AIDB pipeline embeds. Generated, so it can never drift from the signed columns.
ALTER TABLE runbook ADD COLUMN IF NOT EXISTS kb_text text GENERATED ALWAYS AS (title || '. ' || body) STORED;

-- Resolved incidents are the memory: the text a pipeline embeds is the symptom plus the error signatures seen while investigating.
-- A trigger keeps the table in step with `incident` (an incident that is reopened or loses its cause leaves the memory).
CREATE TABLE IF NOT EXISTS incident_memory (
    incident_id  bigint PRIMARY KEY REFERENCES incident(id) ON DELETE CASCADE,
    base         text NOT NULL,
    signatures   text NOT NULL DEFAULT '',
    kb_text      text GENERATED ALWAYS AS (CASE WHEN signatures = '' THEN base ELSE base || ' | ' || signatures END) STORED
);

CREATE OR REPLACE FUNCTION incident_memory_sync() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.status = 'resolved' AND NEW.root_cause_category IS NOT NULL THEN
        INSERT INTO incident_memory (incident_id, base)
        VALUES (NEW.id, COALESCE((SELECT name FROM service WHERE id = NEW.service_id), NEW.service_name, '') || ': ' || NEW.symptom)
        ON CONFLICT (incident_id) DO UPDATE SET base = EXCLUDED.base;
    ELSE
        DELETE FROM incident_memory WHERE incident_id = NEW.id;
    END IF;
    RETURN NEW;
END
$fn$;

DROP TRIGGER IF EXISTS incident_memory_sync ON incident;
CREATE TRIGGER incident_memory_sync AFTER INSERT OR UPDATE OF status, root_cause_category, symptom, service_id ON incident
    FOR EACH ROW EXECUTE FUNCTION incident_memory_sync();

INSERT INTO incident_memory (incident_id, base)
SELECT i.id, COALESCE(s.name, i.service_name, '') || ': ' || i.symptom
FROM incident i LEFT JOIN service s ON s.id = i.service_id
WHERE i.status = 'resolved' AND i.root_cause_category IS NOT NULL
ON CONFLICT (incident_id) DO NOTHING;

-- Investigator methods that use an AIDB agent.
ALTER TABLE run DROP CONSTRAINT IF EXISTS run_mode_check;
ALTER TABLE run ADD CONSTRAINT run_mode_check CHECK (mode IN ('rules', 'llm', 'hybrid', 'aidb', 'aidb_hybrid'));

-- Seals of AIDB agents, purposes, tools, pipelines, models and the evidence views (`apgkit.aidb.seal`); created here so the runtime
-- role, which only verifies, never needs the right to create tables.
CREATE TABLE IF NOT EXISTS apgkit_aidb_seal (
    kind text NOT NULL, name text NOT NULL, mac text NOT NULL, sealed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, name));

-- Fences free text from monitored systems as untrusted data (the AIDB agent's tool results go through this, as the app's own do).
CREATE OR REPLACE FUNCTION pl_fence(t text, n int DEFAULT 300) RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $fn$
    SELECT '<untrusted_data>' || replace(left(COALESCE(t, ''), n), '</untrusted_data>', '[removed]') || '</untrusted_data>'
$fn$;
