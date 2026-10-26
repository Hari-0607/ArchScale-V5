-- =============================================================================
-- Seed 001: Baseline Tenant Types, Roles, Permissions, and Single Platform Org
-- ArchScale V05 Authentication & Authorisation Layer
-- =============================================================================

-- 1. Seed Tenant Types (founder-extensible table)
INSERT INTO tenant_types (key, name, description, is_active)
VALUES
    ('studio_owner', 'Studio Owner', 'Architecture, design, and multi-disciplinary studio tenants', true),
    ('project_owner', 'Project Owner', 'Client developers and capital project sponsors', true),
    ('allied_owner', 'Allied Owner', 'Engineering, contracting, and specialist consulting firms', true)
ON CONFLICT (key) DO NOTHING;

-- 2. Seed Platform Roles (level 50 - 100, portal = 'platform')
INSERT INTO roles (key, name, description, portal, level, min_aal, expiry_required, requires_approval)
VALUES
    ('founder', 'Platform Founder', 'Top platform authority. Manages platform roles, tenant types, global policies, approvals.', 'platform', 100, 'aal2', false, false),
    ('developer', 'Platform Developer', 'Technical operations, readiness checks, migrations, module registry, feature flags, audit read.', 'platform', 70, 'aal2', false, true),
    ('client_servicing', 'Platform Client Servicing', 'Organisation onboarding preparation, access-request support, reasoned support access.', 'platform', 50, 'aal2', false, true),
    ('accounts', 'Platform Accounts', 'Subscriptions, licences, seat allocations, billing, payment status.', 'platform', 50, 'aal2', false, true)
ON CONFLICT (key) DO NOTHING;

-- 3. Seed Subscriber Roles (level 5 - 80, portal = 'subscriber')
INSERT INTO roles (key, name, description, portal, level, min_aal, max_duration, expiry_required, requires_approval)
VALUES
    ('business_owner', 'Business Owner', 'Full control inside the organisation. Manages members, profiles, seats within entitlement ceiling.', 'subscriber', 80, 'aal2', NULL, false, true),
    ('leader', 'Leader', 'Runs teams and projects. Approves executive and intern within scope. Assigns team members.', 'subscriber', 60, 'aal1', NULL, false, true),
    ('manager_coordinator', 'Manager / Coordinator', 'Role family for project/team management with custom access profiles.', 'subscriber', 40, 'aal1', NULL, false, true),
    ('executive', 'Executive', 'Operational contributor. Limited to own records and assigned items.', 'subscriber', 30, 'aal1', NULL, false, true),
    ('intern', 'Intern', 'Least privilege contributor. Read + limited write. Assigned projects only. Expiry required.', 'subscriber', 20, 'aal1', interval '180 days', true, true),
    ('collaborator', 'Collaborator', 'External contributor. Scoped exclusively by active share grants. Time-bound. No directory access.', 'subscriber', 10, 'aal1', interval '90 days', true, true),
    ('guest', 'Guest', 'External read-only visitor. Scoped to shared link / grant. Time-bound. No member visibility.', 'subscriber', 5, 'aal1', interval '30 days', true, true)
ON CONFLICT (key) DO NOTHING;

-- 4. Seed Exactly One Platform Organisation (after roles exist)
INSERT INTO organisations (id, name, portal, tenant_type_key, status)
VALUES
    ('00000000-0000-0000-0000-000000000001', 'ArchScale Platform', 'platform', NULL, 'ACTIVE')
ON CONFLICT DO NOTHING;

-- 5. Seed Role Tenant Types (All subscriber roles are permitted across studio_owner, project_owner, allied_owner)
INSERT INTO role_tenant_types (role_key, tenant_type_key)
SELECT r.key, tt.key
FROM roles r
CROSS JOIN tenant_types tt
WHERE r.portal = 'subscriber'
ON CONFLICT DO NOTHING;

-- 6. Seed Baseline Permissions
INSERT INTO permissions (key, name, description, min_aal)
VALUES
    -- Platform permissions
    ('platform.organisations.review', 'Review Organisations', 'Prepare and review organisation applications', 'aal2'),
    ('platform.organisations.approve', 'Approve Organisations', 'Foundational approval of organisations, entitlements, and seats', 'aal2'),
    ('platform.organisations.suspend', 'Suspend Organisation', 'Suspend or offboard an organisation and kill active sessions', 'aal2'),
    ('platform.roles.manage', 'Manage Platform Roles', 'Create, clone, edit, or retire platform roles', 'aal2'),
    ('platform.support.grant', 'Create Support Access Grant', 'Issue time-boxed, reasoned support access to tenant', 'aal2'),
    ('platform.audit.read', 'Read Platform Audit Logs', 'Read system-wide append-only audit trail', 'aal2'),
    ('platform.billing.manage', 'Manage Billing & Licences', 'Manage subscriptions, licences, and seats', 'aal2'),
    ('platform.dev.diagnostics', 'Technical Diagnostics', 'Run readiness checks, inspect migrations and module registry', 'aal2'),

    -- Subscriber / Organisation permissions
    ('org.workspace.manage', 'Manage Workspaces', 'Create and configure workspaces within organisation', 'aal1'),
    ('org.members.view', 'View Members', 'View member directory within organisation', 'aal1'),
    ('org.members.invite', 'Invite Members', 'Issue invitations to new organisation members', 'aal1'),
    ('org.members.approve', 'Approve Members', 'Approve membership requests within level ceiling', 'aal2'),
    ('org.members.revoke', 'Revoke Membership', 'Revoke or suspend member access', 'aal2'),
    ('org.profiles.manage', 'Manage Access Profiles', 'Create and edit manager_coordinator profiles within ceiling', 'aal1'),
    ('org.seats.manage', 'Manage Seat Allocations', 'Assign app seats to active members within purchased limits', 'aal2'),
    ('org.sharing.create', 'Create Share Grant', 'Issue time-bound record or project share grant', 'aal1'),
    ('org.sharing.revoke', 'Revoke Share Grant', 'Revoke external share grant', 'aal1'),
    ('org.audit.view', 'View Org Audit Logs', 'View organisation audit records', 'aal2'),

    -- Project / Workspace operational permissions
    ('project.records.read', 'Read Project Records', 'Read project records and documents', 'aal1'),
    ('project.records.write', 'Write Project Records', 'Create and edit project records', 'aal1'),
    ('project.records.delete', 'Delete Project Records', 'Delete project records within scope', 'aal1'),
    ('project.team.assign', 'Assign Team Members', 'Assign members to projects and teams', 'aal1')
ON CONFLICT (key) DO NOTHING;

-- 7. Seed Role Permissions
-- Founder
INSERT INTO role_permissions (role_key, permission_key)
SELECT 'founder', key FROM permissions WHERE key LIKE 'platform.%'
ON CONFLICT DO NOTHING;

-- Developer
INSERT INTO role_permissions (role_key, permission_key)
VALUES
    ('developer', 'platform.dev.diagnostics'),
    ('developer', 'platform.audit.read')
ON CONFLICT DO NOTHING;

-- Client Servicing
INSERT INTO role_permissions (role_key, permission_key)
VALUES
    ('client_servicing', 'platform.organisations.review'),
    ('client_servicing', 'platform.support.grant')
ON CONFLICT DO NOTHING;

-- Accounts
INSERT INTO role_permissions (role_key, permission_key)
VALUES
    ('accounts', 'platform.billing.manage')
ON CONFLICT DO NOTHING;

-- Business Owner
INSERT INTO role_permissions (role_key, permission_key)
SELECT 'business_owner', key FROM permissions WHERE key LIKE 'org.%' OR key LIKE 'project.%'
ON CONFLICT DO NOTHING;

-- Leader
INSERT INTO role_permissions (role_key, permission_key)
VALUES
    ('leader', 'org.members.view'),
    ('leader', 'org.members.approve'),
    ('leader', 'org.sharing.create'),
    ('leader', 'project.records.read'),
    ('leader', 'project.records.write'),
    ('leader', 'project.team.assign')
ON CONFLICT DO NOTHING;

-- Manager Coordinator
INSERT INTO role_permissions (role_key, permission_key)
VALUES
    ('manager_coordinator', 'org.members.view'),
    ('manager_coordinator', 'project.records.read'),
    ('manager_coordinator', 'project.records.write'),
    ('manager_coordinator', 'project.team.assign')
ON CONFLICT DO NOTHING;

-- Executive
INSERT INTO role_permissions (role_key, permission_key)
VALUES
    ('executive', 'project.records.read'),
    ('executive', 'project.records.write')
ON CONFLICT DO NOTHING;

-- Intern
INSERT INTO role_permissions (role_key, permission_key)
VALUES
    ('intern', 'project.records.read'),
    ('intern', 'project.records.write')
ON CONFLICT DO NOTHING;

-- Collaborator
INSERT INTO role_permissions (role_key, permission_key)
VALUES
    ('collaborator', 'project.records.read'),
    ('collaborator', 'project.records.write')
ON CONFLICT DO NOTHING;

-- Guest
INSERT INTO role_permissions (role_key, permission_key)
VALUES
    ('guest', 'project.records.read')
ON CONFLICT DO NOTHING;

-- 8. Seed Default Tenant Role Permission Templates (studio_owner baseline)
INSERT INTO tenant_role_permission_templates (tenant_type_key, role_key, permission_key)
SELECT 'studio_owner', role_key, permission_key
FROM role_permissions
WHERE role_key IN ('business_owner', 'leader', 'manager_coordinator', 'executive', 'intern', 'collaborator', 'guest')
ON CONFLICT DO NOTHING;
