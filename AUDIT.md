# XAuth v4.0 Audit — Before Changes

Audit scope: repository contents and local commands only. No staging writes or external Supabase access were performed. Status reflects code present before Phase 2 changes. The referenced assignment PDF is not present in this checkout; the user-provided summary is used as the source of truth.

| Requirement | Status | Evidence | Fix needed | Severity |
|---|---|---|---|---|
| Email/password sign-in and logout | Partial | `src/identity/providers/supabase.ts`; `src/server/index.ts:155,494` | Validate live Supabase flow and browser session expiry handling | High |
| Email verification | Missing | No verification route/flow found in `src/server/index.ts` or UI | Add Supabase verification handling | High |
| Password recovery | Broken | `src/identity/providers/supabase.ts:196-201`; server exposes recovery/reset paths | Implement real Supabase recovery and confirmation | High |
| Real SMTP invitations; lifecycle statuses | Partial | `src/mail/sink.ts`; `src/server/index.ts:1133-1276`; migration 014 | Local path is an in-memory sink; configure SMTP externally; validate accepted/expired transitions | High |
| Invitation acceptance and activation | Partial | `src/server/index.ts:509`; migrations 014-015 | Verify end-to-end against Supabase Auth and resend/revoke race conditions | High |
| JWT verification and token refresh | Partial | `src/identity/providers/supabase.ts`; `src/server/index.ts` | Supabase verification exists; no tested browser refresh/revocation live handling | High |
| Session revocation | Partial | `src/server/index.ts:550-603`; `src/identity/providers/supabase.ts:172-190` | Verify admin API semantics and force connected clients to log out promptly | High |
| Mandatory Platform Super Admin MFA | Partial | `src/authz/decide.ts`; migration 001 roles; tests `tests/server/http_server.test.ts` | Validate enrollment requirement, not only AAL gating, in live flow | Critical |
| Configurable tenant MFA | Partial | migration 014 `member_min_aal`; `src/server/index.ts:1090` | Complete member enrollment policy and verify client behavior | High |
| Backstage tenant CRUD / admin invites / membership lifecycle | Partial | `src/server/index.ts:741-904`; `client/src/pages/backstage/TenantsPage.tsx` | Access assignment and platform role UI incomplete; several routes are placeholders | High |
| Backstage cross-tenant access audited; tenant admins excluded | Partial | migrations 005/013; `src/authz/decide.ts`; `client/src/App.tsx` | UI relies on role checks; prove API and RLS denial for every route | Critical |
| Frontstage invitations, workspace selection, member management | Partial | `client/src/pages/auth/OrgWorkspacePicker.tsx`; `client/src/pages/frontstage/TeamPage.tsx`; server routes | Verify fields, reporting manager management, lifecycle and errors end to end | High |
| Departments, job roles, reporting managers and permission assignment | Partial | migration 014; member profile route `src/server/index.ts:1072`; roles page | Effective-permission preview and complete assignment controls are absent/incomplete | High |
| Tasks and Attendance authorized visibility | Broken | `src/server/index.ts:1283-1488`; frontstage pages | Replace hardcoded in-memory records and role/email checks with tenant data, central authorization and RLS | Critical |
| Profile and session management | Partial | `src/server/index.ts:550-692`; API client | Profile/session UI and live session status are incomplete | Medium |
| Exact 11-member hierarchy and two isolation tenants | Missing | `seeds/001_seed_initial_data.sql`; `scripts/seed_staging_users.ts` | Idempotent 3-tenant/11-member/task/attendance seed is absent | High |
| Tasks schema and required fields (11-25 varied tasks) | Missing | no Tasks SQL tables/migrations; `src/server/index.ts:1283-1400` | Add persistent schema, constraints, audit history and seed data | Critical |
| Task visibility, Design Manager exception and edit boundaries | Broken | `src/server/index.ts:1297-1400`; `client/src/pages/frontstage/TasksPage.tsx` | Move policy to configurable database data; enforce on every API and RLS query | Critical |
| Attendance schema, multi-date records and history | Missing | no Attendance SQL tables/migrations; `src/server/index.ts:1403-1488` | Add persistent records/comments/audit history and seed | Critical |
| Attendance access matrix and denial including URLs/API/exports | Broken | `src/server/index.ts:1417-1488`; UI checks in `AttendancePage.tsx` | Remove email substring authorization; enforce HR Manager edit and Junior HR comment at API and RLS | Critical |
| Central deny-by-default RBAC dimensions/actions | Partial | `src/authz/decide.ts`; `src/config/route_permissions.ts`; migrations 003/013 | Extend to app records, ownership, reporting, approval and configurable exceptions | Critical |
| RBAC enforced in API and RLS | Partial | auth routes use `decide`; migrations 010-015 secure core tables | App record endpoints have no RLS-backed tables or authorization policies | Critical |
| RBAC management UI, matrix, preview, anti-escalation | Partial | `client/src/pages/frontstage/RolesPermissionsPage.tsx`; member role route | Complete editable matrix and effective-permission preview; prevent self-escalation server-side | High |
| Unique identities, immutable creator, reassign audit, deactivation history, IDOR defense | Partial | migrations 001/008/012/014; in-memory task and attendance routes | Persistent app records and scoped record IDs required; preserve creator and append reassignment audit | Critical |
| Modular Tasks / Attendance / XAuth and SDK consumption | Missing | single repository; no SDK package; apps embedded in `src/server/index.ts` | Extract SDK/API contract and register module permissions independently | High |
| Realtime scoped subscriptions and revoked-session logout | Missing | no Realtime subscriptions in `client/src` | Add tenant-scoped realtime and auth state listener after persistent schema exists | High |
| Migrations and idempotent seed | Partial | `migrations/001-015`; `seeds/001-002` | Add ordered app schema/policies and reproducible scenario seed | High |
| SDK/API docs and local/deploy setup | Partial | `docs/PHASE2_RUNBOOK.md`, `postman/archscale_phase2.http` | Publish SDK contract and complete setup instructions | Medium |
| Automated security tests for assignment cases | Partial | `tests/authz`, `tests/migrations`, `tests/server`; no app-data tests | Add app isolation/IDOR/attendance/task policy tests and run against disposable local Supabase/Postgres | Critical |
| No service-role key in browser | Done by source inspection | service key references only in server/config/mail code; `client/src/api/client.ts` calls same-origin server | Keep this boundary and add production bundle scan | Critical |
| No localStorage-only auth | Done by source inspection | `client/src/api/client.ts` keeps bearer token in module memory | Add refresh/revocation handling; current memory-only session does not survive reload | Medium |
| Build, typecheck, lint and tests | Broken / unavailable | `package.json`; command results below | Restore dependency install, then fix compiler/test failures; no lint script exists | High |

## Local command results

- `npm run build` failed: dependencies were missing from `node_modules` (`@supabase/supabase-js`, `express`); this also caused secondary untyped-call and implicit-any TypeScript errors.
- `npm test` first produced no test output and exceeded the command window. A subsequent run failed immediately because `vitest` was not available.
- `npm ci` did not complete; npm exited with `Exit handler never called!`. The environment did not provide enough evidence to distinguish registry/network restriction from an npm defect.
- No `lint` or standalone `typecheck` script is defined. `npm run build` is the configured TypeScript check. `npm run build:ui` was not runnable after the failed install because Vite is unavailable.
- No live Supabase or disposable local database was configured or modified. Staging test suites and destructive data setup were not run.
