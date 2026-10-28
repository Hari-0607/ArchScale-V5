import fs from 'fs';
import pg from 'pg';

// Parse .env natively — never prints values
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
    if (!adminUrl) throw new Error('Missing SUPABASE_DB_ADMIN_URL in .env');

    const client = new pg.Client({ connectionString: adminUrl, ssl: { rejectUnauthorized: false } });
    await client.connect();

    // Open a READ ONLY transaction for all queries
    await client.query('BEGIN TRANSACTION READ ONLY;');

    try {
        console.log('================================================================');
        console.log('ArchScale V05: Staging Read-Only Inspection');
        console.log('Connection: SUPABASE_DB_ADMIN_URL (value not printed)');
        console.log('Transaction mode: READ ONLY');
        console.log('================================================================\n');

        // 1. Platform organisation count
        const platformCount = await client.query(
            `SELECT count(*) AS count FROM organisations WHERE portal = 'platform';`
        );
        console.log('--- 1. Platform organisation count ---');
        console.log(`  count = ${platformCount.rows[0].count}`);

        // 2. All organisations
        const allOrgs = await client.query(
            `SELECT id, name, portal, tenant_type_key, status, created_at
             FROM organisations
             ORDER BY portal, created_at;`
        );
        console.log('\n--- 2. All organisations ---');
        for (const r of allOrgs.rows) {
            console.log(`  [${r.portal}] id=${r.id} name="${r.name}" tenant_type=${r.tenant_type_key ?? 'NULL'} status=${r.status}`);
        }
        console.log(`  total rows: ${allOrgs.rowCount}`);

        // 3. Roles by portal
        const rolesByPortal = await client.query(
            `SELECT portal, count(*) AS count FROM roles GROUP BY portal ORDER BY portal;`
        );
        console.log('\n--- 3. Roles by portal ---');
        for (const r of rolesByPortal.rows) {
            console.log(`  portal=${r.portal} count=${r.count}`);
        }

        // 4. Tenant types
        const tenantTypes = await client.query(
            `SELECT key, name, is_active FROM tenant_types ORDER BY key;`
        );
        console.log('\n--- 4. Tenant types ---');
        for (const r of tenantTypes.rows) {
            console.log(`  key=${r.key} name="${r.name}" is_active=${r.is_active}`);
        }
        console.log(`  total rows: ${tenantTypes.rowCount}`);

        // 5. ALL app_catalogue rows
        const appCatalogue = await client.query(
            `SELECT * FROM app_catalogue ORDER BY created_at NULLS FIRST;`
        );
        console.log('\n--- 5. All app_catalogue rows ---');
        if (appCatalogue.rowCount === 0) {
            console.log('  (empty)');
        } else {
            for (const r of appCatalogue.rows) {
                console.log(`  app_key=${r.app_key} name="${r.name}" created_at=${r.created_at}`);
            }
        }
        console.log(`  total rows: ${appCatalogue.rowCount}`);

        // 6. All public.users rows
        const users = await client.query(
            `SELECT id, user_code, email, created_at FROM public.users ORDER BY created_at;`
        );
        console.log('\n--- 6. All public.users rows ---');
        if (users.rowCount === 0) {
            console.log('  (empty)');
        } else {
            for (const r of users.rows) {
                console.log(`  id=${r.id} user_code=${r.user_code} email=${r.email} created_at=${r.created_at}`);
            }
        }
        console.log(`  total rows: ${users.rowCount}`);

        // 7a. Get audit_logs column names
        const auditCols = await client.query(
            `SELECT column_name FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = 'audit_logs'
             ORDER BY ordinal_position;`
        );
        console.log('\n--- 7a. audit_logs columns ---');
        const colNames = auditCols.rows.map((r: any) => r.column_name);
        console.log('  columns: ' + colNames.join(', '));

        // 7b. ALL audit_logs rows (generic — select only safe known columns)
        const auditLogs = await client.query(
            `SELECT id, action, target_entity, target_id, created_at
             FROM audit_logs
             ORDER BY created_at;`
        );
        console.log('\n--- 7b. All audit_logs rows ---');
        if (auditLogs.rowCount === 0) {
            console.log('  (empty)');
        } else {
            for (const r of auditLogs.rows) {
                console.log(`  id=${r.id} action=${r.action} target_entity=${r.target_entity} target_id=${r.target_id} created_at=${r.created_at}`);
            }
        }
        console.log(`  total audit_logs rows: ${auditLogs.rowCount}`);

        // 7c. Check for TEST_LOG rows specifically
        const testLogs = await client.query(
            `SELECT count(*) AS count FROM audit_logs WHERE action LIKE 'TEST_%';`
        );
        console.log(`  audit_logs rows with action LIKE 'TEST_%': ${testLogs.rows[0].count}`);

        // Done
        await client.query('ROLLBACK;'); // ends READ ONLY transaction cleanly
    } catch (err: any) {
        await client.query('ROLLBACK;').catch(() => {});
        // Redact connection string from error before printing
        let msg = err.message || '';
        try {
            const u = new URL(adminUrl!);
            if (u.password) msg = msg.split(u.password).join('[REDACTED]');
        } catch (_) {}
        console.error('INSPECT ERROR:', msg);
        process.exit(1);
    } finally {
        await client.end();
    }
}

main();
