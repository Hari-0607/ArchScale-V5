-- =============================================================================
-- Seed 002: Phase 2 Protected Route Permissions and Role Assignments
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- 1. Insert Phase 2 Specific Permissions (unified naming, no duplicates with Seed 001)
INSERT INTO public.permissions (key, name, description, min_aal)
VALUES
    ('org.members.read', 'Read Member Directory', 'List and view organisation member roster', 'aal1'),
    ('org.audit.read', 'Read Organisation Audit Logs', 'Read immutable audit trail for own organisation', 'aal2'),
    ('platform.organisations.read', 'Read Platform Organisations', 'Read platform tenant registry and organisation status', 'aal2')
ON CONFLICT (key) DO UPDATE SET min_aal = EXCLUDED.min_aal;

-- 2. Role Assignments
-- business_owner: reads members, invites members (from Seed 001), reads audit logs
INSERT INTO public.role_permissions (role_key, permission_key)
VALUES
    ('business_owner', 'org.members.read'),
    ('business_owner', 'org.members.invite'),
    ('business_owner', 'org.audit.read')
ON CONFLICT (role_key, permission_key) DO NOTHING;

-- leader: reads members only (explicitly NO invite, NO audit read)
INSERT INTO public.role_permissions (role_key, permission_key)
VALUES
    ('leader', 'org.members.read')
ON CONFLICT (role_key, permission_key) DO NOTHING;

-- platform founder: reads platform orgs and platform audit logs
INSERT INTO public.role_permissions (role_key, permission_key)
VALUES
    ('founder', 'platform.organisations.read'),
    ('founder', 'platform.audit.read')
ON CONFLICT (role_key, permission_key) DO NOTHING;

-- client_servicing: reads platform orgs
INSERT INTO public.role_permissions (role_key, permission_key)
VALUES
    ('client_servicing', 'platform.organisations.read')
ON CONFLICT (role_key, permission_key) DO NOTHING;

-- Note: interns, executives, collaborators, and guests do NOT receive org.members.invite, org.audit.read, or platform.organisations.read.
