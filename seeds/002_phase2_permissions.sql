-- =============================================================================
-- Seed 002: Phase 2 Protected Route Permissions and Role Assignments
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- 1. Insert Phase 2 Specific Permissions (unified naming, no duplicates with Seed 001)
INSERT INTO public.permissions (key, name, description, min_aal)
VALUES
    ('org.members.read', 'Read Member Directory', 'List and view organisation member roster', 'aal1'),
    ('org.audit.read', 'Read Organisation Audit Logs', 'Read immutable audit trail for own organisation', 'aal2'),
    ('platform.organisations.read', 'Read Platform Organisations', 'Read platform tenant registry and organisation status', 'aal2'),
    ('org.settings.manage', 'Manage Organisation Settings', 'Manage organisation security settings and MFA requirements', 'aal2'),
    ('org.members.manage', 'Manage Members', 'Change member roles, suspend, or reactivate memberships', 'aal2'),
    ('platform.support.read', 'Support Read Access', 'Read-only inspection access during active support grant', 'aal2'),
    ('platform.support.manage', 'Manage Support Grants', 'Issue and revoke platform support grants', 'aal2'),
    ('platform.organisations.manage', 'Manage Platform Organisations', 'Create, approve, and suspend organisations', 'aal2')
ON CONFLICT (key) DO UPDATE SET min_aal = EXCLUDED.min_aal;

-- 2. Role Assignments
-- business_owner: reads members, invites members (from Seed 001), reads audit logs, manages settings & members
INSERT INTO public.role_permissions (role_key, permission_key)
VALUES
    ('business_owner', 'org.members.read'),
    ('business_owner', 'org.members.invite'),
    ('business_owner', 'org.audit.read'),
    ('business_owner', 'org.settings.manage'),
    ('business_owner', 'org.members.manage')
ON CONFLICT (role_key, permission_key) DO NOTHING;

-- leader: reads members only (explicitly NO invite, NO audit read)
INSERT INTO public.role_permissions (role_key, permission_key)
VALUES
    ('leader', 'org.members.read')
ON CONFLICT (role_key, permission_key) DO NOTHING;

-- platform founder: reads platform orgs and platform audit logs, manages platform orgs & support
INSERT INTO public.role_permissions (role_key, permission_key)
VALUES
    ('founder', 'platform.organisations.read'),
    ('founder', 'platform.audit.read'),
    ('founder', 'platform.organisations.manage'),
    ('founder', 'platform.support.manage'),
    ('founder', 'platform.support.read')
ON CONFLICT (role_key, permission_key) DO NOTHING;

-- client_servicing: reads platform orgs, manages support, reads support
INSERT INTO public.role_permissions (role_key, permission_key)
VALUES
    ('client_servicing', 'platform.organisations.read'),
    ('client_servicing', 'platform.support.manage'),
    ('client_servicing', 'platform.support.read')
ON CONFLICT (role_key, permission_key) DO NOTHING;

-- Note: interns, executives, collaborators, and guests do NOT receive org.members.invite, org.audit.read, or platform.organisations.read.
