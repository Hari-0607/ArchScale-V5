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

async function checkTrigger() {
    const client = new pg.Client({
        connectionString: process.env.SUPABASE_DB_ADMIN_URL,
        ssl: { rejectUnauthorized: false }
    });
    await client.connect();

    const fnRes = await client.query(`
        SELECT p.proname, pg_get_functiondef(p.oid) as def, r.rolname as owner
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'public' AND p.proname = 'rls_auto_enable';
    `);

    const evRes = await client.query(`
        SELECT evtname, evtevent, evtowner::regrole::text as owner, evtfoid::regproc::text as func
        FROM pg_event_trigger
        WHERE evtfoid = 'public.rls_auto_enable'::regproc;
    `);

    console.log('FUNCTION_INFO:', JSON.stringify(fnRes.rows[0], null, 2));
    console.log('EVENT_TRIGGER_INFO:', JSON.stringify(evRes.rows, null, 2));

    await client.end();
}

checkTrigger().catch(err => {
    let msg = err.message || '';
    console.error('ERROR:', msg);
});
