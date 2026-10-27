import fs from 'fs';
import path from 'path';
import pg from 'pg';
import { fileURLToPath } from 'url';

// Parse .env natively
if (fs.existsSync('.env')) {
    const envLines = fs.readFileSync('.env', 'utf-8').split(/\r?\n/);
    for (const line of envLines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
            const idx = trimmed.indexOf('=');
            if (idx !== -1) {
                const key = trimmed.substring(0, idx).trim();
                const val = trimmed.substring(idx + 1).trim();
                if (!process.env[key]) process.env[key] = val;
            }
        }
    }
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
    console.log('======================================================');
    console.log('ArchScale V05: Applying Migrations 001-009 to Staging');
    console.log('======================================================\n');

    // 1. Guardrail: Confirm staging environment
    if (process.env.ARCHSCALE_ENV !== 'staging') {
        console.error('ABORTED: ARCHSCALE_ENV must be set to "staging". Current value:', process.env.ARCHSCALE_ENV);
        process.exit(1);
    }

    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL;
    if (!adminUrl) {
        console.error('ABORTED: SUPABASE_DB_ADMIN_URL is missing in .env');
        process.exit(1);
    }

    // Safety check against production keywords in DB URL
    if (adminUrl.includes('production') || adminUrl.includes('prod-db')) {
        console.error('ABORTED: SUPABASE_DB_ADMIN_URL matches production pattern!');
        process.exit(1);
    }

    const client = new pg.Client({
        connectionString: adminUrl,
        ssl: { rejectUnauthorized: false }
    });

    await client.connect();
    console.log('[1/3] Connected to Supabase PostgreSQL database.');

    const migrationFiles = [
        '001_core_types_and_identities.sql',
        '002_ecosystem_apps_and_entitlements.sql',
        '003_data_driven_roles_and_permissions.sql',
        '004_workspaces_memberships_and_contexts.sql',
        '005_approvals_and_support_access.sql',
        '006_share_grants_and_security_controls.sql',
        '007_append_only_audit_log.sql',
        '008_database_invariants_and_functions.sql',
        '009_least_privilege_runtime_role.sql',
        '010_supabase_staging_compatibility.sql'
    ];

    console.log('\n[2/3] Executing migrations 001-009 sequentially...\n');

    const issues: Array<{ file: string; error: string; code?: string }> = [];

    for (const file of migrationFiles) {
        const filePath = path.join(__dirname, '../migrations', file);
        const sql = fs.readFileSync(filePath, 'utf-8');
        process.stdout.write(`  Applying ${file}... `);
        try {
            await client.query(sql);
            console.log('OK');
        } catch (err: any) {
            console.log('FAILED');
            console.error(`    -> Error [${err.code || 'UNKNOWN'}]: ${err.message}`);
            issues.push({ file, error: err.message, code: err.code });
            // Do not break automatically if partial, but report
            break;
        }
    }

    console.log('\n[3/3] Migration summary:');
    if (issues.length === 0) {
        console.log('All migrations 001-010 applied cleanly without errors!');
        // Synchronize password for dedicated runtime role from .env
        const runtimeUrl = process.env.ARCHSCALE_RUNTIME_DB_URL;
        if (runtimeUrl) {
            try {
                const parsed = new URL(runtimeUrl);
                if (parsed.password) {
                    await client.query(`ALTER ROLE archscale_app_runtime WITH PASSWORD ${client.escapeLiteral(parsed.password)};`);
                    console.log('Dedicated login role archscale_app_runtime password synchronized from .env.');
                }
            } catch (e: any) {
                console.warn('Could not synchronize runtime role password:', e.message);
            }
        }
    } else {
        console.log(`Encountered ${issues.length} issue(s) during migration execution.`);
    }

    await client.end();
}

main().catch(err => {
    console.error('Fatal execution error:', err);
    process.exit(1);
});
