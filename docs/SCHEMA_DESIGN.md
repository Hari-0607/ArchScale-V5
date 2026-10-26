# ArchScale V05 Architecture & Schema Design

## 1. Architectural Philosophy: Organisation-First & Denial-by-Default

ArchScale V05 establishes an organisation-first, data-driven security perimeter. The core architectural invariants are:

1. **Authentication != Authorisation**: Authentication proves identity (`users` mirror). A valid password or session grants zero standing on its own.
2. **Deny by Default**: Every gate must pass; any failure results in strict DENY.
3. **Organisation as Root Entity**: Standing exists solely through an `ACTIVE` membership within an `ACTIVE` organisation.
4. **Roles Attach to Memberships, Never to People**: Roles are data rows evaluated in the context of a specific organisation.
5. **Separation of Authority Paths**: Platform staff belong to a designated Platform Organisation (`portal = 'platform'`). Platform roles have no standing inside subscriber tenants without time-boxed, reasoned, audited support access.
6. **Immutable Audit Trail**: State transitions and approvals are logged to an append-only ledger protected by triggers and privilege revocation.

---

## 2. Lineage: Reused vs. Changed from V05 Reference

| Component | Legacy Pattern | ArchScale V05 Implementation | Status |
| :--- | :--- | :--- | :--- |
| **User Identity** | Roles and tenant references stored on user records. | `users` is an identity mirror (`id`, `user_code`, `email`, `phone`). Zero role/tenant standing. | **REPLACED** |
| **Tenant Types** | Hardcoded enum or application constants. | `tenant_types` table (`key PRIMARY KEY`, `name`, `description`, `is_active`). Extensible at runtime by founders without DDL. | **REPLACED** |
| **Platform Org Isolation** | Superuser flag or bypassed tenant checks. | Single Platform Organisation enforced in SQL via `CREATE UNIQUE INDEX ON organisations ((true)) WHERE portal = 'platform'`. | **REPLACED** |
| **Tenant Nullability** | Arbitrary tenant type assignments. | Enforced by check constraint: `CHECK ((portal = 'platform' AND tenant_type_key IS NULL) OR (portal = 'subscriber' AND tenant_type_key IS NOT NULL))`. | **REPLACED** |
| **Role Matrix** | Code enums (`Role.ADMIN`). | Relational tables (`roles`, `role_permissions`, `tenant_role_permission_templates`, `access_profiles`). Integer levels (0–100) enforce anti-escalation. | **REPLACED** |
| **Permission Grants** | Ad-hoc permission strings. | Exact module-registered keys (`permissions`). Evaluated via role and profile grants. | **REUSED PATTERN** (Hardened into SQL) |
| **Context Lifetime** | Unbounded sessions. | `access_contexts` table with hard check `expires_at <= created_at + interval '24 hours'`, validated via `is_context_valid()`. | **REPLACED** |
| **Audit Logs** | Mutable logs in app files or tables. | `audit_logs` protected by triggers blocking `UPDATE`, `DELETE`, `TRUNCATE`, with privileges revoked from runtime role and public. | **REPLACED** |
| **Approvals** | Code-level if checks. | Stored functions `fn_approve_organisation` and `fn_approve_membership` executing under `SECURITY DEFINER` and `SELECT ... FOR UPDATE` row locks. | **REPLACED** |

---

## 3. Database Invariants & Enforcement Matrix

| Invariant | Enforcement Point | Technical Implementation |
| :--- | :--- | :--- |
| **Single Platform Org** | Table Index | `CREATE UNIQUE INDEX ON organisations ((true)) WHERE portal = 'platform';` |
| **Tenant Type Nullability** | Check Constraint | `CHECK ((portal = 'platform' AND tenant_type_key IS NULL) OR (portal = 'subscriber' AND tenant_type_key IS NOT NULL))` on `organisations` |
| **Separation of Duties** | Database Trigger | `trg_approval_step_invariants` on `approval_steps` aborts if `decider_user_id == requester_user_id` |
| **Level Ceiling** | Database Trigger | `trg_approval_step_invariants` on `approval_steps` aborts if `approver_level <= target_role_level` |
| **Expiry Required Roles** | Database Trigger | `trg_memberships_expiry_enforcement` aborts if `roles.expiry_required = true` and `memberships.expires_at IS NULL` |
| **Active Org Dependency** | Database Trigger | `trg_memberships_org_active_check` aborts activating a membership if parent org `status <> 'ACTIVE'` |
| **Custodian Protection** | Database Trigger | `trg_memberships_custodian_protection` protects last active founder and last active business owner, with suspension exemption |
| **Lifecycle Suspension Cascade** | Database Trigger | `trg_org_suspension_cascade` on `organisations` revokes all active contexts and suspends memberships upon org suspension |
| **Seat Allocation Limit** | Check Constraint + Row Locks | `CHECK (allocated_seats <= seat_limit)` on `organisation_seats` + `SELECT ... FOR UPDATE` in `fn_approve_membership` |
| **Max Context Lifespan** | Check Constraint | `CHECK (expires_at <= created_at + interval '24 hours')` on `access_contexts` |
| **Support Access Rules** | Check + Trigger | `CHECK (expires_at <= started_at + interval '24 hours')` + trigger enforcing platform staff and subscriber target |
| **Single Share Target** | Check Constraint | `CHECK (num_nonnulls(target_org_id, target_user_id) = 1)` on `share_grants` |
| **Audit Immutability** | Triggers + Privileges | `trg_audit_logs_immutable` (UPDATE/DELETE) + `trg_audit_logs_no_truncate` (TRUNCATE) + `REVOKE` privileges |
| **Least Privilege DB Role** | Role Grants | `archscale_app_runtime` has NO SUPERUSER, NO CREATEDB, NO BYPASSRLS, and DDL rights revoked |

---

## 4. Complete Table Directory (27 Tables)

1. `tenant_types`: Founder-extensible tenant types (`studio_owner`, `project_owner`, `allied_owner`).
2. `organisations`: Multi-tenant organization records with status lifecycle and portal type.
3. `users`: Identity mirror records (`id`, `user_code`, `email`, `phone`).
4. `app_catalogue`: Ecosystem application registry.
5. `organisation_entitlements`: Many-to-many licensing linking organisations to licensed apps.
6. `organisation_seats`: Purchased seat limits and allocated counts per app and role.
7. `permissions`: Exact module-registered permission keys.
8. `roles`: Data-driven roles with integer levels, portal segregation, and AAL requirements.
9. `role_tenant_types`: Allowed tenant types per role.
10. `role_permissions`: Core permission mappings per role.
11. `tenant_role_permission_templates`: Default permission templates per (tenant_type x role).
12. `access_profiles`: Custom runtime profiles for role families (e.g. `manager_coordinator` variants).
13. `access_profile_permissions`: Fine-grained permission assignments per profile.
14. `workspaces`: Scoped project/department workspaces within organisations.
15. `memberships`: Binds `(user_id, organisation_id)` with `role_key`, optional `profile_id`, and status.
16. `membership_seats`: Explicit seat allocation bindings.
17. `access_contexts`: Validated 24h context binding User + Session + Org + Workspace + Membership.
18. `invitations`: Hashed token invitation records.
19. `role_assignment_history`: Audit record of membership role mutations.
20. `approval_policies`: Organization approval configuration.
21. `access_requests`: Request records for organization onboarding and membership joining.
22. `approval_steps`: Multi-step routing, decisions, deciders, and justifications.
23. `support_access_grants`: Time-boxed, reasoned platform staff access into tenant data.
24. `share_grants`: Cross-organization and external guest/collaborator record grants.
25. `auth_rate_limits`: Atomic database store for rate limiting.
26. `account_lockouts`: Lockout tracking with administrative unlock.
27. `audit_logs`: Append-only immutable audit ledger.

---

## 5. How to Run Migrations & Test Suites

### Prerequisites
- Node.js v24 LTS
- Live PostgreSQL instance (running on `127.0.0.1:5433` or standard port configured via `PGPORT`)

### Commands
```bash
# Install dependencies
npm install

# Run the complete conformance test suite (7 test files, 29 assertions on real PostgreSQL)
npm test

# Run the end-to-end happy-path and failing-variant walkthrough
npm run walkthrough
```
