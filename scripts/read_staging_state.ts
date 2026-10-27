import fs from 'fs';
import pg from 'pg';

if (fs.existsSync('.env')) {
    const lines = fs.readFileSync('.env', 'utf-8').split(/\r?\n/);
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
            const idx = trimmed.indexOf('=');
            if (idx !== -1) {
                const k = trimmed.substring(0, idx).trim();
                const v = trimmed.substring(idx + 1).trim();
                if (!process.env[k]) process.env[k] = v;
            }
        }
    }
}

async function main() {
    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL;
    if (!adminUrl) throw new Error('Missing SUPABASE_DB_ADMIN_URL');

    const client = new pg.Client({ connectionString: adminUrl, ssl: { rejectUnauthorized: false } });
    await client.connect();

    // 1. Count of platform organisations
    const platformCount = await client.query("SELECT count(*) FROM organisations WHERE portal = 'platform';");

    // 2. Roles by portal
    const rolesByPortal = await client.query("SELECT portal, count(*), array_agg(key ORDER BY level DESC) as role_keys FROM roles GROUP BY portal;");

    // 3. Tenant types
    const tenantTypes = await client.query("SELECT key, name, is_active FROM tenant_types ORDER BY key;");

    // 4. All organisations
    const allOrgs = await client.query("SELECT id, name, portal, tenant_type_key, status, created_at FROM organisations;");

    // 5. Audit logs
    const auditLogs = await client.query("SELECT id, actor_user_id, actor_membership_id, organisation_id, action, target_entity, target_id, diff, client_metadata, created_at FROM audit_logs ORDER BY created_at ASC;");

    console.log('=== STAGING STATE REPORT ===');
    console.log('PLATFORM_ORGS_COUNT:', platformCount.rows[0].count);
    console.log('\nROLES_BY_PORTAL:');
    console.log(JSON.stringify(rolesByPortal.rows, null, 2));
    console.log('\nTENANT_TYPES:');
    console.log(JSON.stringify(tenantTypes.rows, null, 2));
    console.log('\nALL_ORGANISATIONS:');
    console.log(JSON.stringify(allOrgs.rows, null, 2));
    console.log(`\nAUDIT_LOGS (${auditLogs.rows.length} rows):`);
    console.log(JSON.stringify(auditLogs.rows, null, 2));

    await client.end();
}

main().catch(err => {
    console.error('Query failed:', err.message);
    process.exit(1);
});
