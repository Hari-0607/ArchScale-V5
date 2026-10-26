-- =============================================================================
-- Migration 007: Append-Only Audit Log and Immutability Triggers
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Audit Logs Table (Immutable append-only ledger of every security state change)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_membership_id UUID REFERENCES memberships(id) ON DELETE SET NULL,
    organisation_id UUID REFERENCES organisations(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_entity TEXT NOT NULL,
    target_id TEXT NOT NULL,
    diff JSONB,
    client_metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_org_created ON audit_logs(organisation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target_entity, target_id);

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_logs_insert_policy ON audit_logs FOR INSERT WITH CHECK (true);
CREATE POLICY audit_logs_select_policy ON audit_logs FOR SELECT USING (true);

-- -----------------------------------------------------------------------------
-- Trigger: Strictly block UPDATE and DELETE on audit_logs
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_trg_audit_logs_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'SQLSTATE 42501: audit log is append-only. UPDATE and DELETE operations are forbidden.';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;
CREATE TRIGGER trg_audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION fn_trg_audit_logs_immutable();

-- -----------------------------------------------------------------------------
-- Trigger: Strictly block TRUNCATE on audit_logs
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_trg_audit_logs_no_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'SQLSTATE 42501: audit log is append-only. TRUNCATE is forbidden.';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_logs_no_truncate ON audit_logs;
CREATE TRIGGER trg_audit_logs_no_truncate
    BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT
    EXECUTE FUNCTION fn_trg_audit_logs_no_truncate();

-- Revoke mutation privileges from PUBLIC immediately
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM PUBLIC;
