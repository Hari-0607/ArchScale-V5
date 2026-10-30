import { createClient } from '@supabase/supabase-js';
import pg from 'pg';
import '../src/config/env.js';

const env = process.env;
if (env.ARCHSCALE_ENV !== 'development') throw new Error('Local demo seeding requires ARCHSCALE_ENV=development.');

const supabaseUrl = env.SUPABASE_URL || '';
const adminDbUrl = env.SUPABASE_DB_ADMIN_URL || '';
for (const [name, value] of [['SUPABASE_URL', supabaseUrl], ['SUPABASE_DB_ADMIN_URL', adminDbUrl]] as const) {
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error(`${name} must be configured for local demo setup.`); }
  if (!['localhost', '127.0.0.1', '::1'].includes(parsed.hostname)) {
    throw new Error(`${name} must point to loopback for local demo setup.`);
  }
}
if (!env.SUPABASE_SERVICE_ROLE_KEY) throw new Error('SUPABASE_SERVICE_ROLE_KEY is required for local demo setup.');

const accounts = [
  { key: 'owner', email: env.ARCHSCALE_LOCAL_DEMO_EMAIL || 'investigator@example.test', password: env.ARCHSCALE_LOCAL_DEMO_PASSWORD || 'LocalDemo123!', role: 'business_owner', department: 'Management', jobRole: 'Studio Owner', primaryOwner: true },
  { key: 'lead', email: env.ARCHSCALE_LOCAL_MEMBER_EMAIL || 'design.lead@example.test', password: env.ARCHSCALE_LOCAL_MEMBER_PASSWORD || 'LocalLead123!', role: 'leader', department: 'Design', jobRole: 'Lead Architect', primaryOwner: false },
  { key: 'member', email: env.ARCHSCALE_LOCAL_STAFF_EMAIL || 'designer.member@example.test', password: env.ARCHSCALE_LOCAL_STAFF_PASSWORD || 'LocalMember123!', role: 'intern', department: 'Design', jobRole: 'Junior Architect', primaryOwner: false },
  { key: 'partner', email: env.ARCHSCALE_LOCAL_PARTNER_EMAIL || 'partner@example.test', password: env.ARCHSCALE_LOCAL_PARTNER_PASSWORD || 'LocalPartner123!', role: 'collaborator', department: 'External', jobRole: 'Partner Architect', primaryOwner: false },
];
for (const account of accounts) {
  if (account.password.length < 8) throw new Error(`Password for local ${account.key} account must be at least 8 characters.`);
}

const authAdmin = createClient(supabaseUrl, env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});
const { data: listed, error: listError } = await authAdmin.auth.admin.listUsers({ page: 1, perPage: 1000 });
if (listError) throw new Error(`Could not inspect local auth users (${listError.status || 'auth error'}).`);
const existingUsers = new Map(listed.users.map(user => [user.email?.toLowerCase(), user]));
const seededUsers = new Map<string, { id: string; email: string }>();
for (const account of accounts) {
  const existing = existingUsers.get(account.email.toLowerCase());
  if (existing) {
    const { data, error } = await authAdmin.auth.admin.updateUserById(existing.id, { password: account.password, email_confirm: true });
    if (error || !data.user) throw new Error(`Could not reset local ${account.key} account (${error?.status || 'auth error'}).`);
    seededUsers.set(account.key, { id: data.user.id, email: account.email.toLowerCase() });
  } else {
    const { data, error } = await authAdmin.auth.admin.createUser({ email: account.email.toLowerCase(), password: account.password, email_confirm: true });
    if (error || !data.user) throw new Error(`Could not create local ${account.key} account (${error?.status || 'auth error'}).`);
    seededUsers.set(account.key, { id: data.user.id, email: account.email.toLowerCase() });
  }
}

const { Client } = pg;
const db = new Client({ connectionString: adminDbUrl });
await db.connect();
try {
  await db.query('BEGIN');
  for (const account of accounts) {
    const user = seededUsers.get(account.key)!;
    await db.query(
      `INSERT INTO public.users (id, user_code, email)
       VALUES ($1::uuid, 'AS-' || upper(substr(replace($1::text, '-', ''), 1, 8)), $2)
       ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, updated_at = now()`,
      [user.id, user.email],
    );
  }

  const existingOrg = await db.query<{ id: string }>(`SELECT id FROM public.organisations WHERE name = 'ArchScale Local Demo' AND portal = 'subscriber' LIMIT 1`);
  const org = existingOrg.rows[0]
    ? existingOrg
    : await db.query<{ id: string }>(
      `INSERT INTO public.organisations (name, portal, tenant_type_key, status, member_min_aal)
       VALUES ('ArchScale Local Demo', 'subscriber', 'studio_owner', 'ACTIVE', 'aal1') RETURNING id`,
    );
  const orgId = org.rows[0]?.id;
  if (!orgId) throw new Error('Could not create the local demo organisation.');
  await db.query(`UPDATE public.organisations SET status = 'ACTIVE', member_min_aal = 'aal1', updated_at = now() WHERE id = $1`, [orgId]);
  await db.query(
    `INSERT INTO public.workspaces (organisation_id, name, is_default, is_active)
     VALUES ($1, 'Default Workspace', true, true)
     ON CONFLICT (organisation_id, name) DO UPDATE SET is_active = true`,
    [orgId],
  );
  await db.query(
    `INSERT INTO public.organisation_entitlements (organisation_id, app_key, is_enabled)
     SELECT $1, app_key, true FROM public.app_catalogue WHERE app_key IN ('tasks', 'attendance')
     ON CONFLICT (organisation_id, app_key) DO UPDATE SET is_enabled = true`,
    [orgId],
  );

  const owner = await upsertMembership(db, orgId, seededUsers.get('owner')!.id, accounts[0], null, null);
  const lead = await upsertMembership(db, orgId, seededUsers.get('lead')!.id, accounts[1], owner, null);
  await upsertMembership(db, orgId, seededUsers.get('member')!.id, accounts[2], lead, 180);
  await upsertMembership(db, orgId, seededUsers.get('partner')!.id, accounts[3], owner, 90);
  await db.query('COMMIT');
} catch (error) {
  await db.query('ROLLBACK').catch(() => undefined);
  throw error;
} finally {
  await db.end();
}

process.stdout.write('Local demo organization ready with an owner, design lead, staff member, and external partner.\n');

async function upsertMembership(
  client: pg.Client,
  organisationId: string,
  userId: string,
  account: typeof accounts[number],
  managerMembershipId: string | null,
  expiresInDays: number | null,
): Promise<string> {
  const expiresAt = expiresInDays === null ? null : new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000);
  const result = await client.query<{ id: string }>(
    `INSERT INTO public.memberships (
       user_id, organisation_id, role_key, status, is_primary_owner,
       department, job_role, reporting_manager_membership_id, expires_at
     ) VALUES ($1, $2, $3, 'ACTIVE', $4, $5, $6, $7, $8)
     ON CONFLICT (user_id, organisation_id) DO UPDATE SET
       role_key = EXCLUDED.role_key, status = 'ACTIVE', is_primary_owner = EXCLUDED.is_primary_owner,
       department = EXCLUDED.department, job_role = EXCLUDED.job_role,
       reporting_manager_membership_id = EXCLUDED.reporting_manager_membership_id,
       expires_at = EXCLUDED.expires_at, updated_at = now()
     RETURNING id`,
    [userId, organisationId, account.role, account.primaryOwner, account.department, account.jobRole, managerMembershipId, expiresAt],
  );
  return result.rows[0].id;
}

