-- A token that can only scrape /metrics (for the pull agent or a Prometheus server).
ALTER TABLE api_token DROP CONSTRAINT api_token_scope_check;
ALTER TABLE api_token ADD CONSTRAINT api_token_scope_check CHECK (scope IN ('read', 'ingest', 'metrics', 'full'));
