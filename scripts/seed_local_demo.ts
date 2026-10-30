import { createClient } from '@supabase/supabase-js';
import pg from 'pg';
import '../src/config/env.js';

const env = process.env;
if (env.ARCHSCALE_ENV !== 'development') throw new Error('Local demo seeding requires ARCHSCALE_ENV=development.');

const supabaseUrl = env.SUPABASE_URL || '';
const adminDbUrl = env.SUPABASE_DB_ADMIN_URL || '';
const password = env.ARCHSCALE_LOCAL_DEMO_PASSWORD || 'LocalDemo123!';
for (const [name, value] of [['SUPABASE_URL', supabaseUrl], ['SUPABASE_DB_ADMIN_URL', adminDbUrl]] as const) {
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error(`${name} must be configured for local demo setup.`); }
  if (!['localhost', '127.0.0.1', '::1'].includes(parsed.hostname)) {
    throw new Error(`${name} must point to loopback for local demo setup.`);
  }
}
if (!env.SUPABASE_SERVICE_ROLE_KEY) throw new Error('SUPABASE_SERVICE_ROLE_KEY is required for local demo setup.');
if (password.length < 8) throw new Error('ARCHSCALE_LOCAL_DEMO_PASSWORD must be at least 8 characters.');

const email = (env.ARCHSCALE_LOCAL_DEMO_EMAIL || 'investigator@example.test').trim().toLowerCase();
const authAdmin = createClient(supabaseUrl, env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});
const { data: listed, error: listError } = await authAdmin.auth.admin.listUsers({ page: 1, perPage: 1000 });
if (listError) throw new Error(`Could not inspect local auth users (${listError.status || 'auth error'}).`);
let user = listed.users.find((candidate) => candidate.email?.toLowerCase() === email);
if (user) {
  const { data, error } = await authAdmin.auth.admin.updateUserById(user.id, {
    password,
    email_confirm: true,
  });
  if (error || !data.user) throw new Error(`Could not reset local demo password (${error?.status || 'auth error'}).`);
  user = data.user;
} else {
  const { data, error } = await authAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
  });
  if (error || !data.user) throw new Error(`Could not create local demo user (${error?.status || 'auth error'}).`);
  user = data.user;
}

const { Client } = pg;
const db = new Client({ connectionString: adminDbUrl });
await db.connect();
try {
  await db.query('BEGIN');
  await db.query(
    `INSERT INTO public.users (id, user_code, email)
     VALUES ($1::uuid, 'AS-' || upper(substr(replace($1::text, '-', ''), 1, 8)), $2)
     ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, updated_at = now()`,
    [user.id, email],
  );
  const existing = await db.query<{ id: string }>(
    `SELECT id FROM public.organisations
     WHERE name = 'ArchScale Local Demo' AND portal = 'subscriber' LIMIT 1`,
  );
  const org = existing.rows[0]
    ? existing
    : await db.query<{ id: string }>(
      `INSERT INTO public.organisations (name, portal, tenant_type_key, status)
       VALUES ('ArchScale Local Demo', 'subscriber', 'studio_owner', 'ACTIVE')
       RETURNING id`,
    );
  const orgId = org.rows[0]?.id;
  if (!orgId) throw new Error('Could not create the local demo organisation.');
  await db.query(
    `INSERT INTO public.workspaces (organisation_id, name, is_default, is_active)
     VALUES ($1, 'Default Workspace', true, true)
     ON CONFLICT (organisation_id, name) DO UPDATE SET is_active = true`,
    [orgId],
  );
  await db.query(
    `INSERT INTO public.memberships (user_id, organisation_id, role_key, status, is_primary_owner)
     VALUES ($1, $2, 'business_owner', 'ACTIVE', true)
     ON CONFLICT (user_id, organisation_id) DO UPDATE
       SET role_key = 'business_owner', status = 'ACTIVE', is_primary_owner = true, updated_at = now()`,
    [user.id, orgId],
  );
  await db.query(
    `INSERT INTO public.organisation_entitlements (organisation_id, app_key, is_enabled)
     SELECT $1, app_key, true FROM public.app_catalogue
     WHERE app_key IN ('tasks', 'attendance')
     ON CONFLICT (organisation_id, app_key) DO UPDATE SET is_enabled = true`,
    [orgId],
  );
  await db.query('COMMIT');
} catch (error) {
  await db.query('ROLLBACK').catch(() => undefined);
  throw error;
} finally {
  await db.end();
}

process.stdout.write(`Local demo account ready: ${email}\n`);
process.stdout.write('Organisation and default workspace ready; tasks and attendance are enabled when registered in this database.\n');

