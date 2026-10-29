# Local setup and deployment

## Prerequisites

- Node.js 20 or newer and npm.
- Supabase CLI with Docker available for local Supabase.
- A disposable local Supabase instance for migrations and database tests. Do not point the test harness at staging or production.

## Local Supabase

1. Copy `.env.example` to `.env`.
2. Run `supabase init` if this is a fresh local CLI setup, then `supabase start`. Copy the local API URL, anon key, service-role key, and database password from the CLI output into `.env`. Keep `SUPABASE_SERVICE_ROLE_KEY` server-side; never prefix it with `VITE_` or include it in a browser build.
3. Keep `ARCHSCALE_ENV=development`, `SUPABASE_URL` on `127.0.0.1`, and both database URLs on loopback. The application refuses non-loopback URLs in development mode.
4. Run `npm ci`, then `npm run migrate:local`. This applies numbered migrations in order and baseline seeds. It is idempotent at the SQL-object/data level; review a migration before reapplying it to a database containing user data.
5. Configure Supabase Auth email confirmations and SMTP in the local Supabase configuration. Local Supabase routes mail to Inbucket by default. For hosted environments, configure a verified SMTP provider in Supabase Auth and set the redirect URL to `ARCHSCALE_FRONTEND_URL`.
6. Create or invite at least one user, create an active tenant membership and workspace, and enable the `tasks` and `attendance` entitlements before using those apps. The repository does not yet include the requested complete 11-member/3-tenant scenario seed.
7. Start the API with `npm run dev:server`. In another terminal, run `npm run dev:ui`. Use email/password sign-in. Tokens stay in browser memory and are cleared on reload/logout.

## Tests

The migration test harness drops and recreates named isolated databases. Run it only against a disposable loopback PostgreSQL/Supabase database:

```powershell
$env:ARCHSCALE_ENV = 'test'
$env:ALLOW_LOCAL_AUTH = 'true'
$env:ARCHSCALE_TEST_DB_URL = 'postgresql://postgres:YOUR_LOCAL_PASSWORD@127.0.0.1:54322/postgres'
npm test
```

The local database guard rejects non-loopback hosts. `npm run build` runs TypeScript; `npm run build:ui` creates the server-served Vite bundle. There is no lint script yet.

## Hosted staging/deployment

1. Provision a separate Supabase project and record its exact project reference.
2. Apply migrations `001` through `016` in numeric order with a privileged migration connection. Review SQL and inspect the target project before applying; do not run local test helpers against hosted data.
3. Configure `ARCHSCALE_ENV=staging`, exact `ARCHSCALE_STAGING_PROJECT_REF`, the project's URL/anon key, the server-only service-role key, database admin URL and least-privilege runtime URL.
4. Configure SMTP and allowed redirect URLs in Supabase Auth. Set `ARCHSCALE_FRONTEND_URL` to the deployed frontend origin.
5. Build the UI with `npm run build:ui` and API with `npm run build`; deploy the Node server and generated static assets behind HTTPS. Keep service-role/database admin credentials only in server secrets.
6. Create tenant entitlements and app authorization policies for each tenant, then verify access with separate users for each role. Do not treat the local fixture suite as proof of hosted isolation.

## Manual setup still required

- Supabase project keys, SMTP credentials, verified sender/domain, and redirect URLs.
- User account invitations and scenario membership provisioning until the dedicated idempotent seed script is completed.
- Explicit, audited policy rows if platform staff are ever authorized to read tenant app records.
- Realtime design: the current app context is transaction-local, so do not add a direct browser Realtime subscription until a context-bound claim/RLS bridge is implemented.
