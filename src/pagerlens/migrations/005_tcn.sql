-- Live updates: the `tcn` contrib extension (triggered_change_notification) sends a NOTIFY on channel pl_changes for every row
-- change of incident and alert (payload: table, operation, primary key; never row contents). Where the extension is not available
-- the migration still succeeds and the UI falls back to refreshing on its own. Re-run on every start by live.install().
DO $$
BEGIN
    BEGIN
        CREATE EXTENSION IF NOT EXISTS tcn;
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'tcn is not available (%): live updates are off, the pages keep refreshing on a timer', SQLERRM;
    END;
    IF to_regprocedure('triggered_change_notification()') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS incident_tcn ON incident;
        CREATE TRIGGER incident_tcn AFTER INSERT OR UPDATE OR DELETE ON incident
            FOR EACH ROW EXECUTE FUNCTION triggered_change_notification('pl_changes');
        DROP TRIGGER IF EXISTS alert_tcn ON alert;
        CREATE TRIGGER alert_tcn AFTER INSERT OR UPDATE OR DELETE ON alert
            FOR EACH ROW EXECUTE FUNCTION triggered_change_notification('pl_changes');
    END IF;
END $$;
