import fs from 'fs';
import path from 'path';
import { createClient } from '@supabase/supabase-js';
import pg from 'pg';
import { fileURLToPath } from 'url';

// Load .env natively
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

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
    const args = process.argv.slice(2);
    if (!args.includes('--confirm-staging')) {
        console.error('ABORTED: Refusing to run without --confirm-staging flag.');
        process.exit(1);
    }

    const projectRef = process.env.ARCHSCALE_STAGING_PROJECT_REF;
    console.log(`[Staging Cleanup Target] Project Ref: ${projectRef}`);

    const supabaseUrl = process.env.SUPABASE_URL;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const adminDbUrl = process.env.SUPABASE_DB_ADMIN_URL;

    if (!supabaseUrl || !serviceRoleKey || !adminDbUrl) {
        console.error('ABORTED: Missing required Supabase credentials in .env');
        process.exit(1);
    }

    const testUsersPath = path.join(__dirname, '../.local/test-users.json');
    if (!fs.existsSync(testUsersPath)) {
        console.log('No .local/test-users.json found. Nothing to clean.');
        return;
    }

    const testUsers = JSON.parse(fs.readFileSync(testUsersPath, 'utf-8'));
    const adminClient = createClient(supabaseUrl, serviceRoleKey, {
        auth: { persistSession: false, autoRefreshToken: false }
    });

    const pgAdmin = new pg.Client({
        connectionString: adminDbUrl,
        ssl: { rejectUnauthorized: false }
    });
    await pgAdmin.connect();

    try {
        console.log('[Notice] Audit log rows cannot be deleted by design (append-only immutable invariant).');
        for (const [key, user] of Object.entries<any>(testUsers)) {
            // Delete from Supabase Auth
            if (user.id) {
                await adminClient.auth.admin.deleteUser(user.id).catch(() => {});
                // Clean access contexts
                await pgAdmin.query(`DELETE FROM public.access_contexts WHERE user_id = $1::uuid;`, [user.id]).catch(() => {});
                // Clean memberships
                await pgAdmin.query(`DELETE FROM public.memberships WHERE user_id = $1::uuid;`, [user.id]).catch(() => {});
                // Clean public mirror user
                await pgAdmin.query(`DELETE FROM public.users WHERE id = $1::uuid;`, [user.id]).catch(() => {});
                console.log(`  ✓ Cleaned user: ${key} (${user.email})`);
            }
        }
        fs.unlinkSync(testUsersPath);
        console.log('Cleanup finished. .local/test-users.json removed.');
    } finally {
        await pgAdmin.end().catch(() => {});
    }
}

main();

