# Local setup and deployment

hey Iam there

## Prerequisites

- Node.js 20 or newer and npm.
- Supabase CLI with Docker available for local Supabase.
- A disposable local Supabase instance for migrations and database tests. Do not point the test harness at staging or production.

## Local Supabase

1. Copy `.env.example` to `.env`. The checked-in `supabase/config.toml` configures an isolated local Supabase stack on ports 55320–55327. Start Docker Desktop, then run `supabase start` from the repository root. Copy the local API URL, anon key, and service-role key from the CLI output into `.env`. Keep `SUPABASE_SERVICE_ROLE_KEY` server-side; never prefix it with `VITE_` or include it in a browser build.
2. Keep `ARCHSCALE_ENV=development`, `SUPABASE_URL` on `127.0.0.1`, and both database URLs on loopback. The application refuses non-loopback URLs in development mode. Do not replace these with hosted values.
3. Run `npm ci`, then `npm run migrate:local` once against the fresh local database. This applies migrations and baseline seeds in dependency order. The runner does not track previously applied migrations; do not rerun it on an initialized database.
4. Local Supabase routes mail to Inbucket by default. For hosted environments, configure a verified SMTP provider in Supabase Auth and set the redirect URL to `ARCHSCALE_FRONTEND_URL`.
5. Run `npm run seed:local-demo` to create/reset a confirmed local Supabase account and provision its user mirror, active organisation membership, default workspace, and app entitlements. The seed refuses non-loopback Supabase and database URLs. Set `ARCHSCALE_LOCAL_DEMO_EMAIL` and `ARCHSCALE_LOCAL_DEMO_PASSWORD` in `.env` to customize the local credentials.
6. Start the API with `npm run dev:server`. In another terminal, run `npm run dev:ui` and open the URL Vite prints. If port 5173 is already occupied, Vite selects the next available port (for example, 5174). In local development, use **Quick Login (Development)** to sign in to one of the four seeded Supabase accounts, or use the email and password from `.env`. Quick login still uses Supabase Auth and the account's real organisation membership and permissions. Select **ArchScale Local Demo** and **Default Workspace** to continue. Tokens stay in browser memory and are cleared on reload/logout.

### Select the Supabase environment

The running API reads `.env` from the repository root. Local development uses `ARCHSCALE_ENV=development`, loopback URLs, and keys from `supabase start`. Hosted staging uses `ARCHSCALE_ENV=staging` and the URL, keys, database URLs, and exact project reference for that one hosted project. Change the environment variables together; the staging project-reference guard rejects mismatched hosted URLs. Keep real hosted credentials in a private local `.env` or your hosting provider's secret store. Never commit them or put service-role/database credentials in frontend variables.

To confirm which target is configured, check the API process's root `.env` and the dashboard/project reference for that URL. The Supabase Dashboard SQL Editor selection does not change where the app connects. If Docker reports that the daemon is unavailable, start Docker Desktop and wait until `docker info` shows server details, then run `supabase start`.

## Tests

Run the fast, in-memory identity and guard tests without starting Supabase:

```powershell
npx vitest run tests/identity/local_identity.test.ts tests/setup/test_db_guard.test.ts
```

The database-backed suite requires Docker and the local Supabase database to be running. It drops and recreates named isolated test databases, so use only the disposable local database. Run it from PowerShell:

```powershell
$env:ARCHSCALE_ENV = 'test'
$env:ALLOW_LOCAL_AUTH = 'true'
$env:ARCHSCALE_TEST_DB_URL = 'postgresql://postgres:YOUR_LOCAL_PASSWORD@127.0.0.1:55322/postgres'
npm test
```

The test database guard rejects non-loopback hosts. Test mode uses `ARCHSCALE_TEST_DB_URL`; it must never use the app's `ARCHSCALE_RUNTIME_DB_URL`. `npm run build` runs TypeScript; `npm run build:ui` creates the server-served Vite bundle. There is no lint script yet.

## Hosted staging/deployment

1. Provision a separate Supabase project and record its exact project reference.
2. Apply migrations `001` through `016` in numeric order with a privileged migration connection. Review SQL and inspect the target project before applying; do not run local test helpers against hosted data.
3. Configure `ARCHSCALE_ENV=staging`, exact `ARCHSCALE_STAGING_PROJECT_REF`, the project's URL/anon key, the server-only service-role key, database admin URL and least-privilege runtime URL.
4. Configure SMTP and allowed redirect URLs in Supabase Auth. Set `ARCHSCALE_FRONTEND_URL` to the deployed frontend origin.
5. Build the UI with `npm run build:ui` and API with `npm run build`; deploy the Node server and generated static assets behind HTTPS. Keep service-role/database admin credentials only in server secrets.
6. Create tenant entitlements and app authorization policies for each tenant, then verify access with separate users for each role. Do not treat the local fixture suite as proof of hosted isolation.

## Deploy frontend and API to Vercel

The root Express export (`server.ts`) runs the API as a Vercel Node.js Function. Vite builds the frontend into root `public/`, which Vercel serves as static assets under the same origin. The browser continues to call `/api/...`; no separate API host or CORS setup is needed. Vercel does not host the local Supabase stack, so production must use a separate hosted Supabase project and its production database.

Before deploying:

1. Create/select a hosted Supabase production project. Apply migrations `001` through `016` in order using a privileged migration connection, then create the tenant owner. Do not run local test helpers or `npm run migrate:local` against hosted data.
2. Link this folder to the intended Vercel account/project with `vercel link`.
3. Add these Production environment variables in Vercel Project Settings. Keep secrets in Vercel; do not copy them into `.env.example` or commit them:
   - `ARCHSCALE_ENV=production`
   - `ARCHSCALE_PRODUCTION_PROJECT_REF`
   - `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` from that same hosted project
   - `ARCHSCALE_RUNTIME_DB_URL` for the least-privilege runtime role, using the hosted project's session pooler
   - `ARCHSCALE_FRONTEND_URL` set to the production HTTPS domain
4. Add the production domain to Supabase Auth's Site URL and allowed redirect URLs. Never configure the local quick-login accounts or local service-role key in Vercel.
5. Run `npm run build:vercel`, then deploy a Preview with `vercel`. Verify login, organization/workspace selection, and role-based access against the hosted project before promoting with `vercel --prod`.

The production config refuses to start if the hosted project reference, HTTPS URLs, or required runtime settings are missing or inconsistent. This checkout is not currently linked to a Vercel project, and its `.env` contains local Supabase settings only.

### GitHub, Codex, and VS Code

- **GitHub** stores the shared repository and its committed history. It does not run this app's local Supabase stack or supply local `.env` values.
- **VS Code** edits and runs the checkout on this computer. Open the repository root (the folder containing `package.json` and `supabase/config.toml`); run the commands above in its terminal.
- **Codex** can inspect and edit the same checkout when opened as its workspace. Its changes appear as ordinary working-tree changes for you to review in VS Code and commit/push using your normal Git workflow.

Keep `.env` private and commit only safe templates such as `.env.example`. This checkout does not currently contain a Git metadata directory, so GitHub sync/status cannot be performed from this folder until the actual cloned repository is opened.

### Create the first tenant owner

Running SQL migrations creates the schema, but does not create a Supabase Auth user or tenant membership. For a hosted project:

1. In Supabase Dashboard, open **Authentication → Users → Add user**. Create the owner's email/password and confirm the email. Do not create users by inserting rows into `auth.users` from SQL.
2. Configure this app's `.env` with that project's API URL, anon key, server-only service-role key, database admin URL, runtime database URL, `ARCHSCALE_ENV=staging`, and `ARCHSCALE_STAGING_PROJECT_REF`. The project reference is the subdomain in the project API URL.
3. Run this once with the exact project reference and owner email:

   ```powershell
   npm run bootstrap:tenant-owner -- --confirm-project=<PROJECT_REF> "Organisation name" owner@example.com
   ```

   This creates an active subscriber organisation, default workspace, Tasks and Attendance entitlements, user mirror, and active `business_owner` membership. The command refuses a project reference mismatch. It does not print or pass passwords through the shell. Run it only once per intended organisation.
4. Sign in with the Auth email/password. The workspace picker should show the new organisation and **Default Workspace**.

If sign-in still fails, verify the user exists and is confirmed under **Authentication → Users**, and that the app server's `SUPABASE_URL` and `SUPABASE_ANON_KEY` belong to the same Supabase project as the Auth user. A Supabase SQL editor tab does not determine which project the running app is connected to.

## Manual setup still required

- Supabase project keys, SMTP credentials, verified sender/domain, and redirect URLs.
- User account invitations and scenario membership provisioning until the dedicated idempotent seed script is completed.
- Explicit, audited policy rows if platform staff are ever authorized to read tenant app records.
- Realtime design: the current app context is transaction-local, so do not add a direct browser Realtime subscription until a context-bound claim/RLS bridge is implemented.
