import fs from 'fs';
import pg from 'pg';

// Parse .env natively
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

async function inspectPublic() {
    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL;
    if (!adminUrl) {
        throw new Error('SUPABASE_DB_ADMIN_URL missing in .env');
    }

    const client = new pg.Client({
        connectionString: adminUrl,
        ssl: { rejectUnauthorized: false }
    });

    await client.connect();

    // 1. Tables
    const tables = await client.query(`
        SELECT tablename 
        FROM pg_tables 
        WHERE schemaname = 'public'
        ORDER BY tablename;
    `);

    // 2. Types
    const types = await client.query(`
        SELECT t.typname
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = 'public' AND t.typtype = 'e'
        ORDER BY t.typname;
    `);

    // 3. Functions
    const functions = await client.query(`
        SELECT routine_name
        FROM information_schema.routines
        WHERE routine_schema = 'public'
        ORDER BY routine_name;
    `);

    // 4. Triggers
    const triggers = await client.query(`
        SELECT trigger_name, event_object_table
        FROM information_schema.triggers
        WHERE trigger_schema = 'public'
        ORDER BY trigger_name;
    `);

    // 5. Indexes
    const indexes = await client.query(`
        SELECT indexname, tablename
        FROM pg_indexes
        WHERE schemaname = 'public'
        ORDER BY indexname;
    `);

    console.log(JSON.stringify({
        tables: tables.rows.map(r => r.tablename),
        types: types.rows.map(r => r.typname),
        functions: functions.rows.map(r => r.routine_name),
        triggers: triggers.rows.map(r => ({ trigger: r.trigger_name, table: r.event_object_table })),
        indexes: indexes.rows.map(r => ({ index: r.indexname, table: r.tablename }))
    }, null, 2));

    await client.end();
}

inspectPublic().catch(err => {
    let msg = err.message || '';
    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL;
    if (adminUrl) {
        try {
            const u = new URL(adminUrl);
            if (u.password) msg = msg.split(u.password).join('[REDACTED]');
        } catch (_) {}
    }
    console.error('INSPECT_FAILED:', msg);
    process.exit(1);
});
