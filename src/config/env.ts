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

    // Staging guardrail: refuse to run unless ARCHSCALE_ENV is 'staging' (or unit test with explicit local auth)
    if (env !== 'staging' && !(nodeEnv === 'test' && allowLocalAuth)) {
        throw new Error(
            `ABORTED: Execution refused. ARCHSCALE_ENV must be explicitly set to 'staging' (current: '${env || 'undefined'}').`
        );
    }

    // Safety checks against production URLs in staging
    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL || '';
    const runtimeUrl = process.env.ARCHSCALE_RUNTIME_DB_URL || '';
    const supabaseUrl = process.env.SUPABASE_URL || '';

    if (
        adminUrl.includes('prod-db') ||
        adminUrl.includes('production') ||
        runtimeUrl.includes('prod-db') ||
        supabaseUrl.includes('prod-')
    ) {
        throw new Error('ABORTED: Production URL pattern detected in staging environment variables.');
    }

    if (env === 'staging') {
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
