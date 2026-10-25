-- Retiring a service deletes the service and its telemetry but keeps the incident history: the incident forgets the
-- service row and keeps its name (set when the service is retired, or when the incident is opened).
ALTER TABLE incident ADD COLUMN service_name text;
ALTER TABLE incident ALTER COLUMN service_id DROP NOT NULL;
ALTER TABLE incident DROP CONSTRAINT incident_service_id_fkey;
ALTER TABLE incident ADD CONSTRAINT incident_service_id_fkey FOREIGN KEY (service_id) REFERENCES service(id) ON DELETE SET NULL;
