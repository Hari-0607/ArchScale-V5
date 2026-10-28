import fs from 'fs';
import path from 'path';

// Native .env parser (never logs or echoes values)
export function loadEnvFile(filePath = '.env'): void {
    if (!fs.existsSync(filePath)) return;
    const lines = fs.readFileSync(filePath, 'utf-8').split(/\r?\n/);
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
            const idx = trimmed.indexOf('=');
            if (idx !== -1) {
                const k = trimmed.substring(0, idx).trim();
                const v = trimmed.substring(idx + 1).trim();
                if (!process.env[k]) {
                    process.env[k] = v;
                }
            }
        }
    }
}

// Auto-load .env
loadEnvFile();

export interface AppConfig {
    env: 'staging' | 'production' | 'test' | 'development';
    nodeEnv: string;
    supabaseUrl: string;
    supabaseAnonKey: string;
    supabaseServiceRoleKey: string;
    supabaseDbAdminUrl: string;
    archscaleRuntimeDbUrl: string;
    archscaleTestDbUrl?: string;
    allowLocalAuth: boolean;
}

export function validateConfig(): AppConfig {
    const nodeEnv = process.env.NODE_ENV || 'development';
    const env = (process.env.ARCHSCALE_ENV || '').toLowerCase() as AppConfig['env'];
    const allowLocalAuth = process.env.ALLOW_LOCAL_AUTH === 'true';

    // Staging guardrail: refuse to run unless ARCHSCALE_ENV is 'staging'
    // (or unit test with explicit local auth)
    if (env !== 'staging' && !(nodeEnv === 'test' && allowLocalAuth)) {
        throw new Error(
            `ABORTED: Execution refused. ARCHSCALE_ENV must be explicitly set to 'staging' (current: '${env || 'undefined'}').`
        );
    }

    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL || '';
    const runtimeUrl = process.env.ARCHSCALE_RUNTIME_DB_URL || '';
    const supabaseUrl = process.env.SUPABASE_URL || '';

    if (env === 'staging') {
        // ---------------------------------------------------------------------------
        // Project-ref allowlist guard (replaces the old pattern-based check)
        //
        // ARCHSCALE_STAGING_PROJECT_REF must be set explicitly.
        // The project ref must appear verbatim in SUPABASE_URL and in the DB host
        // of SUPABASE_DB_ADMIN_URL.  We extract and compare the subdomain exactly —
        // no substring fuzzing.
        // ---------------------------------------------------------------------------
        const projectRef = process.env.ARCHSCALE_STAGING_PROJECT_REF || '';
        if (!projectRef) {
            throw new Error(
                'ABORTED: ARCHSCALE_STAGING_PROJECT_REF is not set. ' +
                'Add it to .env (see .env.example). Do not push the value.'
            );
        }

        // Parse and validate SUPABASE_URL contains exact project ref
        let supabaseHost = '';
        try {
            supabaseHost = new URL(supabaseUrl).hostname; // e.g. "xyzref.supabase.co"
        } catch {
            throw new Error('ABORTED: SUPABASE_URL is not a valid URL.');
        }
        // supabaseHost should be exactly "<projectRef>.supabase.co"
        if (supabaseHost.split('.')[0] !== projectRef) {
            throw new Error(
                `ABORTED: SUPABASE_URL hostname '${supabaseHost}' does not match ` +
                `ARCHSCALE_STAGING_PROJECT_REF '${projectRef}'. ` +
                `Expected subdomain to be exactly '${projectRef}'.`
            );
        }

        // Parse and validate DB admin URL contains exact project ref in the username
        // Supabase pooler usernames are: postgres.<projectRef>
        let dbAdminUser = '';
        try {
            dbAdminUser = new URL(adminUrl).username; // e.g. "postgres.xyzref"
        } catch {
            throw new Error('ABORTED: SUPABASE_DB_ADMIN_URL is not a valid URL.');
        }
        const dbRefPart = dbAdminUser.split('.').pop() || ''; // last segment of user
        if (dbRefPart !== projectRef) {
            throw new Error(
                `ABORTED: SUPABASE_DB_ADMIN_URL username '${dbAdminUser}' does not contain ` +
                `ARCHSCALE_STAGING_PROJECT_REF '${projectRef}' as the project segment. ` +
                `Expected username to end with '.${projectRef}'.`
            );
        }

        // Validate required variables
        const missing: string[] = [];
        if (!process.env.SUPABASE_URL) missing.push('SUPABASE_URL');
        if (!process.env.SUPABASE_ANON_KEY) missing.push('SUPABASE_ANON_KEY');
        if (!process.env.SUPABASE_SERVICE_ROLE_KEY) missing.push('SUPABASE_SERVICE_ROLE_KEY');
        if (!process.env.SUPABASE_DB_ADMIN_URL) missing.push('SUPABASE_DB_ADMIN_URL');
        if (!process.env.ARCHSCALE_RUNTIME_DB_URL) missing.push('ARCHSCALE_RUNTIME_DB_URL');

        if (missing.length > 0) {
            throw new Error(`ABORTED: Missing required environment variables: ${missing.join(', ')}`);
        }
    }

    return {
        env,
        nodeEnv,
        supabaseUrl,
        supabaseAnonKey: process.env.SUPABASE_ANON_KEY || '',
        supabaseServiceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY || '',
        supabaseDbAdminUrl: adminUrl,
        archscaleRuntimeDbUrl: runtimeUrl,
        archscaleTestDbUrl: process.env.ARCHSCALE_TEST_DB_URL,
        allowLocalAuth
    };
}

export const config = validateConfig();
