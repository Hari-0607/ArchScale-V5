# ArchScale V05 Architecture & Schema Design

## 1. Architectural Philosophy: Organisation-First & Denial-by-Default

ArchScale V05 repudiates user-centric authentication patterns. In conventional systems, a user record possesses permissions, global roles, or direct tenant associations. ArchScale V05 operates under strict invariants:

1. **Authentication != Authorisation**: A valid authentication credential establishes *who you are* (a person with a unique identity record), but provides **zero standing** inside the ecosystem.
2. **Organisation as Root Entity**: Access rights exist solely through an `ACTIVE` membership within an `ACTIVE` organisation.
3. **Roles Attach to Memberships, Never to People**: A person may be a `business_owner` in Org A and an `intern` in Org B. Context resolution isolates these scopes entirely.
4. **Segregation of Authority Paths**: Platform staff belong to a designated Platform Organisation (`portal = 'platform'`). Platform credentials have zero implicit access to subscriber tenant records, and subscriber credentials cannot reach platform administrative endpoints.
5. **Server-Resolved Ground Truth**: Client headers and payloads provide untrusted selectors (such as a requested context ID). The server evaluates identity, session, membership, organisation lifecycle, entitlements, and AAL levels before returning an `ALLOW`.

---

## 2. Lineage: Reuse vs. Replace (from Reference Architecture)

| Component | Legacy / Reference Pattern | ArchScale V05 Implementation | Status |
| :--- | :--- | :--- | :--- |
| **User Table** | Contained role column, organization IDs, or admin flags. | `users` is an identity-mirror table (`id`, `user_code`, `email`, `phone`). Zero role, tenant, or entitlement columns. | **REPLACED** |
| **Tenant Types** | Hardcoded code enum or config constants. | `tenant_types` table (`key PRIMARY KEY`, `name`, `description`, `is_active`). Founder-extensible at runtime without DDL or redeployment. | **REPLACED** |
| **Platform Authority** | Superuser bypass flag or wildcard role. | Segregated platform organisation (`portal = 'platform'`), enforced by partial unique index `((true)) WHERE portal = 'platform'`. Platform roles never work in tenant scopes without time-boxed `support_access_grants`. | **REPLACED** |
| **Role Matrix** | Static TypeScript/Python enums (`Role.ADMIN`). | Data-driven tables (`roles`, `role_permissions`, `tenant_role_permission_templates`, `access_profiles`). Level integer ceilings (0-100) enforce anti-privilege escalation in SQL. | **REPLACED** |
| **Permission Evaluation** | Implicit grant logic or client claim checks. | Exact module-registered permission keys evaluated against membership role/profile and verified context. | **REUSED PATTERN** (Adopted from `permission_grants` & `grant_covers` concept, hardened into SQL) |
| **Context Lifespan** | Long-lived session tokens with unvalidated tenant switching. | `access_contexts` binding (user, session, org, workspace, membership, aal_level) with hard max 24h lifespan (`CHECK (expires_at <= created_at + interval '24 hours')`) validated via `is_context_valid()`. | **REPLACED** |
| **Audit Trails** | Mutable or best-effort log records. | Append-only `audit_logs` table protected by immutability triggers (blocking `UPDATE`, `DELETE`, `TRUNCATE`) and privilege revocation. | **REPLACED** |

---

## 3. Database Schema Blueprint (Migrations 001 - 004)

### Migration 001: Core Types & Identities
- **Enums**:
  - `org_status`: `APPLIED`, `PENDING_REVIEW`, `APPROVED`, `ACTIVE`, `SUSPENDED`, `OFFBOARDED`
  - `membership_status`: `INVITED`, `REQUESTED`, `PENDING_APPROVAL`, `APPROVED`, `REJECTED`, `ACTIVE`, `SUSPENDED`, `EXPIRED`, `REVOKED`
  - `request_status`: `PENDING`, `APPROVED`, `REJECTED`, `CANCELLED`
  - `portal_type`: `platform`, `subscriber`
  - `aal_level`: `aal1`, `aal2`, `aal3`
- **Tables**:
  - `tenant_types`: Founder-extensible catalogue (`studio_owner`, `project_owner`, `allied_owner`).
  - `organisations`:
    - Enforces single platform organisation:
      ```sql
      CREATE UNIQUE INDEX idx_single_platform_org ON organisations ((true)) WHERE portal = 'platform';
      ```
    - Enforces tenant type nullability rule:
      ```sql
      CONSTRAINT chk_org_portal_tenant_type CHECK (
        (portal = 'platform' AND tenant_type_key IS NULL) OR 
        (portal = 'subscriber' AND tenant_type_key IS NOT NULL)
      )
      ```
  - `users`: Identity mirror with unique `user_code` and contact info; strictly no standing or authorization data.
- **RLS**: Row-Level Security enabled on all tables from creation.

### Migration 002: Ecosystem Apps & Entitlements
- **Tables**:
  - `app_catalogue`: Applications registered in ArchScale with eligible tenant types.
  - `organisation_entitlements`: Many-to-many licensing linking organisations to licensed apps.
  - `organisation_seats`:
    - Defines seat limits per (organisation, app, role).
    - Hard check: `CONSTRAINT chk_seats_allocated_lte_limit CHECK (allocated_seats <= seat_limit)`.
- **RLS**: Row-Level Security enabled on all tables from creation.

### Migration 003: Data-Driven Roles & Permissions
- **Tables**:
  - `permissions`: Exact module-registered permission strings (e.g., `org.members.manage`, `billing.invoices.view`).
  - `roles`: Role definitions with integer level (0-100), portal segregation, minimum AAL, and expiry requirements.
  - `role_tenant_types`: Allowed tenant types per role.
  - `role_permissions`: Core permission mapping per role.
  - `tenant_role_permission_templates`: Default permission templates per (tenant_type x role).
  - `access_profiles`: Custom runtime profiles for role families (e.g. `manager_coordinator` profiles).
  - `access_profile_permissions`: Fine-grained permission assignments per profile.
- **Seeds**:
  - Seeds default tenant types (`studio_owner`, `project_owner`, `allied_owner`).
  - Seeds the single Platform Organisation (`portal = 'platform'`, `name = 'ArchScale Platform'`, `status = 'ACTIVE'`).
  - Seeds Platform roles (`founder` lvl 100 AAL2, `developer` lvl 70, `client_servicing` lvl 50, `accounts` lvl 50).
  - Seeds Subscriber roles (`business_owner` lvl 80 AAL2, `leader` lvl 60, `manager_coordinator` lvl 40, `executive` lvl 30, `intern` lvl 20 [expiry required], `collaborator` lvl 10 [expiry required], `guest` lvl 5 [expiry required]).
  - Seeds permission matrix and role associations.
- **RLS**: Row-Level Security enabled on all tables from creation.

### Migration 004: Workspaces, Memberships, & Contexts
- **Tables**:
  - `workspaces`: Scoped project/department workspaces within organisations.
  - `memberships`:
    - Links `(user_id, organisation_id)` with `role_key`, optional `profile_id`, status, and optional `expires_at`.
    - Unique constraint: exactly one membership per user per organisation (`UNIQUE (user_id, organisation_id)`).
  - `membership_seats`: Explicit seat allocation linking membership to an app.
  - `access_contexts`:
    - Context binding `(user_id, session_id, organisation_id, workspace_id, membership_id, aal_level)`.
    - Hard check: `CONSTRAINT chk_context_max_24h CHECK (expires_at <= created_at + interval '24 hours')`.
  - `invitations`: Hashed token invitation records.
  - `role_assignment_history`: Audit record of membership role changes.
- **Validation Function**:
  - `is_context_valid(p_context_id UUID) -> BOOLEAN`:
    Validates that `revoked_at IS NULL`, `expires_at > now()`, `membership.status = 'ACTIVE'`, `membership.expires_at > now()`, `organisation.status = 'ACTIVE'`, and `workspace.is_active = true`.
- **RLS**: Row-Level Security enabled on all tables from creation.
