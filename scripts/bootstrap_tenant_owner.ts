import { createClient } from '@supabase/supabase-js';
import pg from 'pg';
import '../src/config/env.js';

/**
 * One-time hosted bootstrap for a subscriber tenant and an existing Auth user.
 * Never run this on an existing tenant unless you intend to create another.
 */
const env = process.env;
const match = process.argv.find(arg => arg.startsWith('--confirm-project='));
const confirmedProject = match?.slice('--confirm-project='.length);
if (!confirmedProject) {
  throw new Error('Usage: npx tsx scripts/bootstrap_tenant_owner.ts --confirm-project=<SUPABASE_PROJECT_REF>');
}
if (!['staging', 'production'].includes(env.ARCHSCALE_ENV || '')) {
  throw new Error('Set ARCHSCALE_ENV=staging or production for hosted bootstrap.');
}
if (confirmedProject !== env.ARCHSCALE_STAGING_PROJECT_REF) {
  throw new Error('The confirmed project reference must match ARCHSCALE_STAGING_PROJECT_REF.');
}

const supabaseUrl = env.SUPABASE_URL || '';
const adminDbUrl = env.SUPABASE_DB_ADMIN_URL || '';
const supabaseHost = new URL(supabaseUrl).hostname;
const dbUrl = new URL(adminDbUrl);
if (supabaseHost !== `${confirmedProject}.supabase.co` || !dbUrl.username.endsWith(`.${confirmedProject}`)) {
  throw new Error('Supabase API URL and database admin URL must both identify the confirmed project.');
}
if (!env.SUPABASE_SERVICE_ROLE_KEY || !env.SUPABASE_DB_ADMIN_URL) {
  throw new Error('SUPABASE_SERVICE_ROLE_KEY and SUPABASE_DB_ADMIN_URL must be configured server-side.');
}

const [name, emailArg] = process.argv.slice(2).filter(arg => !arg.startsWith('--'));
const email = emailArg?.trim().toLowerCase();
if (!name || name.trim().length < 2 || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
  throw new Error('Usage: npx tsx scripts/bootstrap_tenant_owner.ts --confirm-project=<REF> "Organisation name" owner@example.com');
}

const authAdmin = createClient(supabaseUrl, env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});
const db = new pg.Client({
  connectionString: adminDbUrl,
  ssl: { rejectUnauthorized: true },
  connectionTimeoutMillis: 15000,
});

const { data: listed, error: listError } = await authAdmin.auth.admin.listUsers({ page: 1, perPage: 1000 });
if (listError) throw new Error(`Could not inspect Supabase Auth users (${listError.status || 'auth error'}).`);
const authUser = listed.users.find(user => user.email?.toLowerCase() === email);
if (!authUser) {
  throw new Error(`No Supabase Auth user exists for ${email}. Create and confirm that user in Supabase Dashboard > Authentication > Users first.`);
}

try {
  await db.connect();
  await db.query('BEGIN');
  const user = authUser;
  await db.query(
    `INSERT INTO public.users (id, user_code, email)
     VALUES ($1::uuid, 'AS-' || upper(substr(replace($1::text, '-', ''), 1, 8)), $2)
     ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, updated_at = now()`,
    [user.id, email],
  );

  const org = await db.query<{ id: string }>(
    `INSERT INTO public.organisations (name, portal, tenant_type_key, status, member_min_aal)
     VALUES ($1, 'subscriber', 'studio_owner', 'ACTIVE', 'aal1') RETURNING id`,
    [name.trim()],
  );
  const orgId = org.rows[0]?.id;
  if (!orgId) throw new Error('Could not create the organisation.');

  await db.query(
    `INSERT INTO public.workspaces (organisation_id, name, is_default, is_active)
     VALUES ($1, 'Default Workspace', true, true)`,
    [orgId],
  );
  await db.query(
    `INSERT INTO public.organisation_entitlements (organisation_id, app_key, is_enabled)
     SELECT $1, app_key, true FROM public.app_catalogue
     WHERE app_key IN ('tasks', 'attendance')
     ON CONFLICT (organisation_id, app_key) DO UPDATE SET is_enabled = true`,
    [orgId],
  );
  await db.query(
    `INSERT INTO public.memberships (user_id, organisation_id, role_key, status, is_primary_owner, department, job_role)
     VALUES ($1::uuid, $2::uuid, 'business_owner', 'ACTIVE', true, 'Management', 'Organisation Owner')`,
    [user.id, orgId],
  );
  await db.query('COMMIT');
  process.stdout.write(`Created organisation "${name.trim()}" for ${email}.\n`);
  process.stdout.write('The owner can now sign in and select Default Workspace.\n');
} catch (error) {
  await db.query('ROLLBACK').catch(() => undefined);
  throw error;
} finally {
  await db.end().catch(() => undefined);
}
