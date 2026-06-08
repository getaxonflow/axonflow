-- Down migration for 118: drop the portal_session_lookup SECURITY DEFINER helper.
BEGIN;
DROP FUNCTION IF EXISTS portal_session_lookup(VARCHAR);
COMMIT;
