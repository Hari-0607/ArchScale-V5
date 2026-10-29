# XAuth v4.0 Implementation Status — After Changes

This status is based on code changes and commands run in this workspace. Database migrations were not applied because no disposable local Supabase database was available.

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Email/password login and logout | Partial | Supabase provider exists; server verification remains; no browser refresh lifecycle. |
| Email verification | Partial | Supabase Auth can enforce it by project setting; no frontend confirmation flow. |
| Password recovery | Partial | Recovery email and recovery-token password update are implemented server-side; recovery screens and live delivery are pending. |
| SMTP invitations and all lifecycle states | Partial | Supabase Auth Admin dispatch and invitation tables exist; delivery requires external SMTP and lifecycle was not exercised. |
| Invitation acceptance and activation | Partial | Database and route implementations exist; no complete frontend acceptance flow or live validation. |
| JWT verification / refresh / session revocation | Partial | Live token verification exists; refresh and multi-session revocation semantics require Supabase integration testing. |
| Mandatory Platform Super Admin MFA | Partial | Context role AAL gates exist and MFA API is bound to access tokens; factor enrollment and recovery are not complete. |
| Configurable tenant MFA | Partial | Database setting and API exist; enrollment/UI and end-to-end checks remain. |
| Backstage tenant CRUD, tenant admin invitation, membership lifecycle | Partial | Existing routes/UI; audited cross-tenant and role assignment coverage is incomplete. |
| Tenant Admin denied Backstage; support access audited | Partial | Server route permissions and context constraints exist; UI still uses client role presentation and needs complete route matrix tests. |
| Frontstage workspace, members, departments and hierarchy | Partial | Workspace picker and member routes exist; CRUD and reporting-manager usability are incomplete. |
| RBAC role/permission assignment and effective preview | Partial | Current screen contains fixture policy data; a live configurable editor/preview and anti-escalation workflow remain. |
| Persistent Tasks schema, required fields, audit and RLS | Partial | Migration 016 and database-backed endpoints added; not applied or tested against PostgreSQL. |
| Tasks visibility / Design Manager exception / junior field limits | Partial | Data-driven policy rows and RLS/trigger checks added; no automated conformance tests or configurable extra peer grants UI. |
| Persistent Attendance schema, comments and audit | Partial | Migration 016, RLS and actor-bound comments added; not applied or tested against PostgreSQL. |
| Attendance access matrix, including API/IDOR denial | Partial | Role/email handler checks removed; policy rows enforce HR access in RLS, pending matrix tests and audited Super Admin read grants. |
| Central deny-by-default app policy | Partial | `fn_app_record_allowed` checks active context, tenant entitlement, role permission and configured policy; integration with all existing `decide()` routes is incomplete. |
| API and RLS enforcement | Partial | Task/attendance access uses forced RLS and shared SQL policy evaluator; SQL execution and HTTP tests are pending. |
| Unique IDs, creator ownership, reassignment history and deactivation | Partial | UUID/public IDs, actor-bound creator, immutable tenant/creator and append-only audit triggers added; verify with database tests. |
| Reusable SDK and independent consuming apps | Partial | Source SDK package created and bundled frontend consumes it; separate Tasks/Attendance repositories and lifecycle tests are absent. |
| Supabase Realtime and immediate session logout | Missing | No tenant-scoped realtime bridge. Transaction-local app context needs a secure realtime claim design first. |
| Exact three-tenant / eleven-member / tasks / attendance seed | Missing | Baseline seeds remain; scenario fixture requiring account provisioning has not been implemented. |
| Ordered migrations and local setup | Partial | Local migration runner and setup docs added; migration 016 has not been executed. |
| Automated tests for assignment security cases | Missing | Existing suite requires a configured disposable local database; no app-level matrix tests were added. |
| Service-role key absent from browser | Done by source inspection | Service key remains server-side; frontend talks to the API and SDK only. |
| No hardcoded task/attendance records or client-supplied persona authorization | Done by source inspection | In-memory app record arrays and trust in `X-Demo-Persona` were removed; demo login is test-only. |
| Build, typecheck and lint | Partial | TypeScript and Vite builds pass; lint is not configured. |
| Test report, setup and SDK docs | Partial | Documents exist; they explicitly list unverified and blocked work. |
