# ArchScale V05 | Phase 1 Live Proof Demo Harness

A standalone local demonstration harness that proves, live and against the real PostgreSQL 18 database, that all Phase 1 multi-tenant authorization invariants and security rules are strictly enforced at the database layer.

---

## Safety Guarantees

1. **Localhost Bound Only**: The HTTP demo server binds exclusively to `127.0.0.1` and explicitly rejects non-loopback clients.
2. **Least-Privilege Execution**: All 14 rule checks execute strictly as `archscale_app_runtime` (NO SUPERUSER, NO CREATEDB, NO BYPASSRLS, and DDL rights revoked). The active role is displayed live on the header.
3. **Transaction Rollback Guarantee**: Every rule check runs inside an isolated transaction with a `SAVEPOINT` and is **ALWAYS rolled back**. Rejection checks leave zero residual test data in the database.
4. **Zero Hardcoded Credentials**: Connection parameters and flags are read directly from environment variables.
5. **No Modifications to Core**: This harness does not modify any migration file or portal application code.

---

## How to Start the Demo Server

### Default Execution (Read-Only Panel 1 & 2)
```bash
node demo/server.js
```
The server will start at: **`http://127.0.0.1:3001`**

### With Live Walkthrough Enabled (DEMO_MODE=true)
In PowerShell:
```powershell
$env:DEMO_MODE="true"
node demo/server.js
```
Or inline in Linux / macOS / Bash:
```bash
DEMO_MODE=true node demo/server.js
```

---

## Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PGHOST` | `127.0.0.1` | PostgreSQL database host |
| `PGPORT` | `5433` | PostgreSQL database port |
| `PGUSER` | `archscale_app_runtime` | Database role (least-privilege runtime role) |
| `PGPASSWORD` | `archscale_runtime_local_pass` | Password for the runtime role |
| `PGDATABASE` | `archscale_phase1_clean` | Target database instance |
| `DEMO_PORT` | `3001` | HTTP port for the demo UI |
| `DEMO_MODE` | `false` | Must be `true` to enable Panel 3 committed walkthrough |

---

## Panel Breakdown

### Panel 1: Rule Enforcement Checks (14 Rules)
Executes 14 specific security invariant tests against PostgreSQL inside isolated, rolled-back transactions:
1. **Single Platform Organisation**: Rejecting second root platform organization (`idx_single_platform_org` / RLS).
2. **Audit Log UPDATE**: Rejecting mutation attempts via `fn_trg_audit_logs_immutable` / privilege revocation.
3. **Audit Log DELETE**: Rejecting deletion attempts via `fn_trg_audit_logs_immutable`.
4. **Audit Log TRUNCATE**: Rejecting bulk truncation via `fn_trg_audit_logs_no_truncate`.
5. **Active Membership Dependency**: Rejecting active memberships under `APPLIED` organizations (`trg_memberships_org_active_check`).
6. **Custodian Protection**: Rejecting suspension or removal of the last active platform founder (`fn_trg_custodian_protection`).
7. **Expiry Enforcement for Interns**: Rejecting intern creation without expiration timestamp (`trg_memberships_expiry_enforcement`).
8. **Share Grant Mutual Exclusivity**: Rejecting grants specifying both `target_org_id` and `target_user_id` (`chk_share_grant_target_one`).
9. **Support Access 24h Lifespan**: Rejecting support grants with exceeding 24h expiration (`chk_support_grant_max_24h`).
10. **Separation of Duties**: Rejecting self-approval attempts (`trg_approval_step_invariants`).
11. **Forged Actor Defense**: Rejecting approval requests passing fictitious or cross-tenant approvers (`fn_approve_membership`).
12. **Organisation Suspension Exemption**: Demonstrating that parent organization suspension is exempt from custodian locks and cascades to revoke contexts.
13. **Row-Level Security (RLS) Isolation**: Proving `archscale_app_runtime` receives 0 rows when querying tenant data without an active context.
14. **Least-Privilege Privilege Proof**: Proving `archscale_app_runtime` lacks `rolsuper`, `rolbypassrls`, and cannot execute DDL (`CREATE TABLE`).

**Status Semantics**:
- `PASS` (Green): Database rejected the statement with the expected error class (or succeeded for exemption/RLS proofs).
- `FAIL` (Red): Statement illegally succeeded when rejection was required.
- `Not built yet` (Grey): Object or column does not exist (`42P01` or `42703`).

### Panel 2: Live Database State (Auto-Refreshed Every 3 Seconds)
Directly queries live database tables without caching:
- Counts of organizations grouped by status (`APPLIED`, `ACTIVE`, `SUSPENDED`).
- Counts of memberships grouped by status.
- Platform & Subscriber roles listed by key and integer authority level.
- Registered tenant types (`studio_owner`, `project_owner`, `allied_owner`).
- Total immutable audit logs count.
- Live feed of the 5 most recent audit entries.

### Panel 3: Live Approval Walkthrough (Dedicated Demo Organisation)
Requires `DEMO_MODE=true`. Runs the committed happy path + deliberate failure on a uniquely tagged DEMO organization:
1. Creates an `APPLIED` demo organization.
2. Platform Founder approves onboarding via `fn_approve_organisation`.
3. Business Owner approves a Leader via `fn_approve_membership`.
4. Business Owner approves an Intern with 90-day expiry.
5. Attempts second intern when seats are exhausted (1/1): verifies database rejection with zero partial data.
6. Suspends the demo organization and verifies context revocation and membership cascading.
