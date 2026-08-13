DROP TRIGGER IF EXISTS audit_events_no_mutate ON audit_events;
DROP FUNCTION IF EXISTS audit_events_append_only();
DROP TABLE IF EXISTS audit_events;
