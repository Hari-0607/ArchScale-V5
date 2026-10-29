# Test report

## Passed

- `npm ci` — completed from the lockfile. npm reported 6 dependency vulnerabilities (3 moderate, 1 high, 2 critical); no `npm audit fix` was applied.
- `npm run build` — TypeScript compilation passed after typing the PostgreSQL client boundary.
- `npm run build:ui` — Vite production build passed.

## Security checks

- `npm ci` reported 6 dependency advisories (3 moderate, 1 high, 2 critical).
- `npm audit --json` could not retrieve advisory details because `registry.npmjs.org` DNS/network access was unavailable. No forced dependency upgrades were applied.

## Failed

- `npm test` — 21 test suites failed during collection before any tests ran. The required `ARCHSCALE_TEST_DB_URL` was not configured; `tests/setup/db_connection.ts` intentionally rejects missing or non-loopback databases. No staging or production database was touched.

## Pending

- Migration 016 application and SQL syntax/runtime validation against disposable local Supabase.
- Existing 99-test database suite against a configured disposable database.
- Task/attendance automated API and RLS tests: tenant isolation, Design Manager visibility vs edit/reassign, junior isolation, approval authority, Attendance matrix, IDOR, deactivation, and module removal/reinstallation.
- Invitation lifecycle and SMTP delivery in Supabase; email verification and recovery UI; mandatory MFA enrollment and session-revocation behavior.
- Three-tenant, exact 11-member seed plus 11–25 tasks and multi-date attendance fixture.
- Supabase Realtime subscriptions and immediate revoked-session logout.
- Backstage/frontstage role matrix, effective-permission preview, and permission-management tests.
- Independent SDK consumer apps and deployment validation.
- Lint: no lint script is configured.

These pending items were not represented as passing because no local database or Supabase SMTP credentials were supplied, and migration 016 has not been applied in this environment.
