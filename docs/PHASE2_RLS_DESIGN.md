# Phase 2 Step 2 — RLS and authorisation design

Status: **design only**. Do not implement until this document is approved.

This step gives `archscale_app_runtime` a working membership list, context create / renew / revoke, and `decide()`, without opening tables to unvalidated GUCs. Every policy below must re-check `is_context_valid()` (or call `fn_current_context_user_id()`, which already does). Bare `current_setting('archscale.current_context_id')` is forbidden in policies.

Migration 010 already ENABLE + FORCE RLS on public tables in staging. Local tests enable RLS but do not FORCE it on the table owner. Runtime is `NOBYPASSRLS`, so missing policies already mean zero rows for that role.

---

## Non-negotiable rules

1. Target organisation, workspace, role, profile, portal, and tenant type come from the **database row bound to the access context**, never from request JSON or headers. Injected `organisation_id`, `role_key`, or similar are ignored.
2. The caller must name organisation and workspace explicitly. Never default to “first membership” or “default workspace”.
3. Context lifetime is `least(now() + 24 hours, membership.expires_at)` and the table check `expires_at <= created_at + interval '24 hours'` remains the hard cap.
4. Platform standing and tenant standing are separate paths. A platform role may enter a subscriber organisation only with an **ACTIVE** `support_access_grants` row (not revoked, `expires_at > now()`, staff membership is the actor’s platform membership, target organisation matches).
5. Clients see a short reason code. The long reason is written only to `audit_logs`.
6. Audit every context create / renew / revoke and every `DENY` from `decide()`.

---

## Prerequisite: `is_context_valid(uuid)` must become SECURITY DEFINER

Today `is_context_valid(uuid)` is `LANGUAGE sql STABLE` **invoker**. Runtime `SELECT` on `access_contexts` / `memberships` / `organisations` / `workspaces` with no policy returns zero rows, so the function is always false for the runtime role (and `fn_set_app_context` would always raise).

Step 2 migration must:

- Recreate `is_context_valid(uuid)` as `SECURITY DEFINER` with `SET search_path = public, pg_temp`.
- Keep the parameterless `is_context_valid()` from 012 (safe `NULLIF` GUC cast).
- Keep `fn_set_app_context` as the only way to set `archscale.current_context_id` (`is_local = true`).

Until that change, **no context-bound RLS policy can work for runtime**.

---

## 1. Listing memberships before a context exists (login time)

There is no access context at login. Context-bound RLS therefore cannot list memberships.

**Application contract**

- After `verify()`, TypeScript calls the database with `principal.id` from the identity provider only.
- Request body / query `user_id` is ignored.

**Database**

- `fn_list_principal_memberships(p_user_id uuid)` `SECURITY DEFINER`.
  - Returns memberships for that user only: `membership_id`, `organisation_id`, org `name`, `portal`, `tenant_type_key`, org `status`, `role_key`, membership `status`, `expires_at`, `profile_id`.
  - Does **not** create a context and does **not** pick a workspace.
- `fn_list_org_workspaces_for_principal(p_user_id uuid, p_organisation_id uuid)` `SECURITY DEFINER`.
  - Succeeds only if that user has a membership row for that organisation (any status is returned so the client can show “suspended”; create-context still requires ACTIVE).
  - Returns workspaces of that organisation (`id`, `name`, `is_default`, `is_active`). Still does not pick one.

**Why not a policy?** RLS cannot bind “the verified principal of this HTTP request” without a JWT claim in Postgres. A GUC set by the app would be forgeable unless a definer function sets it after the app already decided the user id — which is the same trust as passing `p_user_id`. The definer function plus “TypeScript uses `principal.id` only” is the control.

Grant `EXECUTE` on both functions to `archscale_app_runtime`. Direct `SELECT` on `memberships` / `workspaces` remains policy-restricted (see table matrix).

---

## 2. Context create: one SECURITY DEFINER function

`fn_create_access_context(p_user_id uuid, p_session_id text, p_organisation_id uuid, p_workspace_id uuid, p_aal aal_level)`

Single transaction. Validates **user + session + membership + organisation + workspace** (and entitlements / support grant) before insert. Returns the new context id or raises with a stable error code the app maps to a client reason code.

| Check | Fail closed when |
| :--- | :--- |
| User | no `public.users` row for `p_user_id` |
| Session | `p_session_id` is null/blank (provider session already verified in app; DB stores the id, it does not call Supabase) |
| Organisation | missing, or `status <> 'ACTIVE'` |
| Workspace | missing, `is_active = false`, or `organisation_id` ≠ `p_organisation_id` |
| Membership | no row for `(p_user_id, p_organisation_id)`, or `status <> 'ACTIVE'`, or `expires_at` in the past |
| Role vs portal | `roles.portal` must match `organisations.portal` for this membership |
| Role vs tenant type | subscriber: `(role_key, tenant_type_key)` exists in `role_tenant_types` |
| Entitlements | subscriber: at least one `organisation_entitlements` row with `is_enabled = true` (platform org is exempt) |
| Platform into tenant | if actor role `portal = 'platform'` **and** target org `portal = 'subscriber'`: require an ACTIVE support grant (see below). Creating a context **in** the platform org does not need a grant |
| Lifetime | `expires_at = least(now() + interval '24 hours', membership.expires_at)` (if membership expiry is null, `now() + 24 hours`) |
| AAL stored | `aal_level` column = `p_aal` from the **verified principal**, not from the client |

Insert into `access_contexts`. Append audit `context.create`. Do not write role or org from caller-supplied JSON.

**Renew:** `fn_renew_access_context(p_context_id uuid, p_user_id uuid, p_session_id uuid-or-text)`  
Re-run the same membership / org / workspace / entitlement / grant checks against the **existing** context’s bound ids (not new ids from the client). Set `expires_at = least(now() + 24 hours, membership.expires_at)` still constrained by `created_at + 24 hours` — if `created_at + 24 hours` is in the past, refuse and require a new context. Audit `context.renew`.

**Revoke:** `fn_revoke_access_context(p_context_id uuid, p_user_id uuid, p_session_id text)`  
Sets `revoked_at = now()` only if `user_id` and `session_id` match. Logout in app: provider `revokeSession` **and** this function. Audit `context.revoke`.

Direct `INSERT`/`UPDATE` on `access_contexts` by runtime is revoked; only these functions write.

---

## 3. Audit writes when the context is invalid

`decide()` must log denials for forged, expired, or missing contexts. A policy that requires `is_context_valid()` on `INSERT` would drop those rows.

**Replace** migration 007’s open policies (`WITH CHECK (true)` / `USING (true)`):

- `REVOKE INSERT, SELECT ON audit_logs FROM archscale_app_runtime` then grant only through functions.
- `fn_audit_append(...)` `SECURITY DEFINER`: inserts one row. Callable **with or without** a valid context. Used for denials, context lifecycle, and later approvals.
- `fn_audit_read_for_context()` or a SELECT policy: `is_context_valid() AND organisation_id = (organisation of current context)` for subscriber; platform `platform.audit.read` is a later route, not an open SELECT.

Immutability triggers stay. Runtime never gets `UPDATE`/`DELETE`/`TRUNCATE`.

**Rule a policy cannot express:** “INSERT allowed with no context for denials; SELECT allowed only with a valid context in-scope.” That split is function-based, not a single RLS policy.

---

## 4. Global reference data — who may read

These catalogues have no tenant owner. They are needed by `decide()` and by membership listing.

| Table | Who may read | How |
| :--- | :--- | :--- |
| `tenant_types` | runtime, with **or without** a context (login + decide) | `SELECT` policy `USING (true)` **or** fold into definer functions. No INSERT/UPDATE for runtime |
| `roles` | same | SELECT of active rows; writes are founder-only later (not Step 2) |
| `permissions` | same | SELECT |
| `role_permissions` | same | SELECT (decide Gate 6) |
| `role_tenant_types` | same | SELECT (context create + Gate 5) |
| `tenant_role_permission_templates` | same | SELECT; templates are not a live grant — live grant is `role_permissions` plus `access_profile_permissions` |

`USING (true)` on catalogues is acceptable because they are not tenant data and contain no PII. Prefer **SELECT-only** policies, `TO archscale_app_runtime`, no write.

`access_profiles` / `access_profile_permissions` are **per organisation**, not global — see matrix.

---

## 5. `decide()` gates (proposed for approval)

TypeScript `decide()` loads facts through definer functions / `is_context_valid`, never from the request body. First failing gate wins. Client reason codes are short; audit `diff` holds `{ gate, detail }`.

| Gate | Question | Client reason code (illustrative) |
| :--- | :--- | :--- |
| **0** | Context row exists, `context.user_id = principal.id`, `context.session_id = principal.sessionId` | `AUTH_CONTEXT_MISMATCH` |
| **1** | `is_context_valid(context.id)` is true (not revoked, not expired, membership ACTIVE and unexpired, org ACTIVE, workspace active) | `AUTH_CONTEXT_INVALID` |
| **2** | Organisation facts from the **context’s** `organisation_id` (status ACTIVE already in Gate 1; portal/tenant_type used later) | `AUTH_ORG_INACTIVE` |
| **3** | Membership facts from the **context’s** `membership_id` (role_key, profile_id, status). Ignore JSON/header role | `AUTH_MEMBERSHIP` |
| **4** | Workspace facts from the **context’s** `workspace_id`; must belong to that organisation | `AUTH_WORKSPACE` |
| **5** | Portal path: platform role in platform org; subscriber role in subscriber org; **platform role + subscriber org** requires ACTIVE `support_access_grants`. Tenant role on a platform route denied | `AUTH_PORTAL` / `AUTH_SUPPORT_GRANT` |
| **6** | Route permission map: required `permission` is granted via `role_permissions` and, if `profile_id` set, also present in `access_profile_permissions` (profile **narrows**, it does not add keys the role lacks unless we document the opposite — **proposal: profile is a subset filter when present**). `deniedRoles` on the route (intern, executive on invite) deny even if a stray grant exists | `AUTH_PERMISSION` |
| **7** | `principal.aal` ≥ `max(roles.min_aal, permissions.min_aal)` for the membership role and the route permission | `AUTH_AAL` |
| **8** | If the route names an `app_key`, `organisation_entitlements` for that org+app is `is_enabled`. Platform routes skip. Seats are not re-checked on every request in Step 2 (allocation is an approval-time invariant); flag if you want Gate 8 to include `membership_seats` | `AUTH_ENTITLEMENT` |

Staff (`client_servicing`, `developer`, `accounts`, `founder`) on tenant data: Gate 7 will deny `aal1` because platform roles seed `min_aal = aal2`. That matches “staff at aal1 denied, at aal2 allowed” for platform-min-aal routes; subscriber `leader` at aal1 remains allowed on `aal1` permissions.

---

## 6. Table matrix (runtime in Step 2)

Legend: **P** = context-bound RLS using `is_context_valid()` / `fn_current_context_user_id()`. **F** = `SECURITY DEFINER` function (no direct access, or SELECT-only plus function writes). **G** = global catalogue SELECT. **N** = no runtime write in Step 2.

### memberships

- **Need:** list at login; re-read on create/renew/decide; no runtime UPDATE in Step 2 (status changes stay with existing triggers / `fn_approve_membership`).
- **Access:** **F** `fn_list_principal_memberships`; **P** SELECT `USING (is_context_valid() AND user_id = fn_current_context_user_id() AND organisation_id = <context org>)` so decide can read the bound row after `fn_set_app_context`. Direct INSERT/UPDATE revoked (keep existing definer approvers).
- **Cannot express in a policy:** listing **other** orgs’ memberships for the same user **before** a context exists.

### workspaces

- **Need:** list for a chosen org at login; bind on create; decide Gate 4.
- **Access:** **F** `fn_list_org_workspaces_for_principal`; **P** SELECT where `organisation_id` = context org and `is_context_valid()`. Direct INSERT/UPDATE revoked in Step 2 (`org.workspace.manage` is a later write path).

### access_contexts

- **Need:** create / renew / revoke / decide.
- **Access:** **F** only (`fn_create_access_context`, `fn_renew_access_context`, `fn_revoke_access_context`, plus `fn_set_app_context` / `is_context_valid`). **No** SELECT policy that returns other users’ contexts. Optional **P** SELECT of **own** row: `id` = GUC id **and** `is_context_valid()` **and** `user_id = fn_current_context_user_id()`.
- **Cannot express:** create-time validation of session + membership + org + workspace + grant in one atomic insert — that is the definer function.

### organisations

- **Need:** name, portal, status, tenant_type for list, create, decide.
- **Access:** **F** for login listing (join inside membership function). **P** SELECT `id = context organisation_id AND is_context_valid()`. Direct UPDATE revoked (suspension stays owner/definer).
- **Cannot express:** “show orgs I belong to before a context exists” as a single org policy without leaking other tenants.

### roles, permissions, role_permissions, role_tenant_types, tenant_role_permission_templates

- **Need:** Gates 5–7 and create-time portal/tenant checks.
- **Access:** **G** SELECT-only for runtime. Writes **N**.

### access_profiles

- **Need:** decide Gate 6 when `memberships.profile_id` is set.
- **Access:** **P** SELECT `organisation_id = context org AND is_context_valid()`. Writes **N** in Step 2.

### access_profile_permissions

- **Need:** Gate 6 subset filter.
- **Access:** **P** SELECT via join to `access_profiles` of the context org, `is_context_valid()`. Writes **N**.

### organisation_entitlements

- **Need:** create/renew and Gate 8.
- **Access:** **P** SELECT `organisation_id = context org AND is_context_valid()`. Create-time check is inside `fn_create_access_context` (definer) because there is no context yet. Writes **N**.

### organisation_seats

- **Need:** not for `decide()` in Step 2 (seat math lives in `fn_approve_membership`). Read later for billing UI.
- **Access:** **P** SELECT same-org, `is_context_valid()`. Direct UPDATE revoked (definer already updates allocated_seats). **Flag:** Step 2 app will not call seat writes.

### membership_seats

- **Need:** optional proof that the membership holds a seat for an `app_key`.
- **Access:** **P** SELECT where membership is the context membership and `is_context_valid()`. Writes **N**. **Flag:** Gate 8 will **not** require a membership_seat row unless you approve that extra rule (collaborators/guests may lack seats).

### support_access_grants

- **Need:** Gate 5 and create-context for platform-into-tenant.
- **Access:** runtime must **not** SELECT all grants. **F** `fn_active_support_grant(p_staff_membership_id, p_target_org_id)` returns grant id or null. Optional **P** SELECT for platform-context users of grants they issued — defer; Step 2 only needs the function.
- **Cannot express:** “grant is ACTIVE, not expired, not revoked, staff membership is platform, target is this subscriber org, and the current context user owns that staff membership” as a simple org-id equality policy without leaking other tenants’ grants.

### share_grants

- **Need:** not evaluated in Step 2 `decide()` (no record API). Still lock the table.
- **Access:** **P** SELECT `source_organisation_id = context org AND is_context_valid()` OR (`target_org_id = context org` and valid context). Writes **N**. **Flag:** resource-level share checks cannot be a table policy on `share_grants` alone; they belong in a later record-level function.

### audit_logs

- **Need:** append on lifecycle + every DENY; later SELECT in-org.
- **Access:** **F** `fn_audit_append` (no valid context required). SELECT **P** in-org after valid context, or platform read in a later step. Drop `USING (true)` / `WITH CHECK (true)`.

### approval_policies, access_requests, approval_steps

- **Need:** none in Step 2 routes (no approve endpoints). Existing `fn_approve_organisation` / `fn_approve_membership` stay the only writers.
- **Access:** Direct INSERT/UPDATE revoked for runtime (already intended; confirm GRANT). **P** SELECT same-org + `is_context_valid()` so we do not leave FORCE RLS with zero policies if something selects. Writes remain **F**.
- **Cannot express:** separation of duties and level ceiling — already triggers, not RLS.

### users (already 012)

- SELECT own row via `fn_current_context_user_id()`. Writes only `fn_upsert_user_mirror`. Unchanged in Step 2.

---

## 7. File layout (Step 2 implementation, after approval)

```
migrations/013_context_rls_and_authz_functions.sql
  is_context_valid(uuid) SECURITY DEFINER
  fn_list_principal_memberships
  fn_list_org_workspaces_for_principal
  fn_create_access_context
  fn_renew_access_context
  fn_revoke_access_context
  fn_active_support_grant
  fn_audit_append
  RLS policies per table above
  REVOKE direct writes on access_contexts, memberships, …

src/authz/reasons.ts          -- client reason codes
src/authz/route_map.ts        -- ROUTE_PERMISSIONS
src/authz/types.ts
src/authz/decide.ts           -- decide()
src/context/memberships.ts    -- list memberships / workspaces (principal.id only)
src/context/access_context.ts -- create / renew / revoke
src/audit/append.ts           -- wrapper around fn_audit_append

tests/authz/01_denials.test.ts
tests/authz/02_allowed.test.ts
tests/migrations/09_context_rls_and_functions.test.ts
```

No UI, no password reset, no MFA enrolment, no lockout endpoints.

---

## 8. `decide()` signature and route permission map

```ts
export type ReasonCode =
  | 'AUTH_CONTEXT_MISMATCH'
  | 'AUTH_CONTEXT_INVALID'
  | 'AUTH_ORG_INACTIVE'
  | 'AUTH_MEMBERSHIP'
  | 'AUTH_WORKSPACE'
  | 'AUTH_PORTAL'
  | 'AUTH_SUPPORT_GRANT'
  | 'AUTH_PERMISSION'
  | 'AUTH_AAL'
  | 'AUTH_ENTITLEMENT';

export interface DecisionAllow {
  allow: true;
  contextId: string;
  userId: string;
  organisationId: string;
  workspaceId: string;
  membershipId: string;
  roleKey: string;
  portal: 'platform' | 'subscriber';
  tenantTypeKey: string | null;
}

export interface DecisionDeny {
  allow: false;
  reasonCode: ReasonCode;
}

export type Decision = DecisionAllow | DecisionDeny;

export async function decide(input: {
  principal: VerifiedPrincipal;
  contextId: string;
  routeKey: string;
}): Promise<Decision>;
```

`decide` looks up `routeKey` in the map (unknown route = deny `AUTH_PERMISSION`). It does not take organisation, workspace, or role from `input` besides `contextId` and `principal`.

```ts
export interface RoutePermission {
  permission: string;
  portal: 'platform' | 'subscriber';
  appKey?: string;
  deniedRoleKeys?: string[];
}

export const ROUTE_PERMISSIONS: Record<string, RoutePermission> = {
  'org.members.invite': {
    permission: 'org.members.invite',
    portal: 'subscriber',
    deniedRoleKeys: ['intern', 'executive'],
  },
  // further keys registered with each route; unknown key => deny
};
```

Platform routes set `portal: 'platform'` (tenant roles fail Gate 5). Invite is the Step 2 example that intern/executive must fail even if a test tampers with grants.

---

## 9. Test plan (implementation order, after approval)

Denial tests first, local DB, constructed `VerifiedPrincipal` (no UI):

- no membership
- organisation not ACTIVE
- membership suspended or expired
- forged or other-user context id
- expired context
- revoked provider session (session id mismatch / Gate 0)
- role or organisation in JSON or headers ignored
- platform role into tenant without grant
- expired or revoked grant
- tenant role to a platform route
- intern or executive on invite route
- two-membership user: owner rights only in the owning organisation
- staff at aal1 denied, aal2 allowed

Then allowed paths per role, renewal, logout revoking provider session and context.

Run only Step 2 test files while developing; full local suite once at the end.

---

## 10. Flags for review

1. Gate 6: when `profile_id` is set, treat profile permissions as a **subset** of the role (not a union). Confirm.
2. Gate 8: subscriber context create requires **any** enabled entitlement; routes with `appKey` require that app. Platform org exempt. Confirm.
3. `membership_seats` not in Gate 8 for Step 2. Confirm.
4. `share_grants` unused by `decide()` in Step 2. Confirm.
5. Convert `is_context_valid(uuid)` to SECURITY DEFINER (required). Confirm.
6. Approval tables: SELECT policies only; no new approve APIs. Confirm.
