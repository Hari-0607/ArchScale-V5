import pg from 'pg';
import { config } from '../config/env.js';

const { Pool } = pg;

export function assertLocalTestDatabaseGuard(url: string | undefined): URL {
    if (!url) {
        throw new Error('SECURITY VIOLATION: Missing ARCHSCALE_TEST_DB_URL in environment for local tests.');
    }
    let parsed: URL;
    try {
        parsed = new URL(url);
    } catch {
        throw new Error('SECURITY VIOLATION: ARCHSCALE_TEST_DB_URL is not a valid URL.');
    }

    const host = parsed.hostname.toLowerCase();
    if (host !== '127.0.0.1' && host !== 'localhost') {
        throw new Error(`SECURITY VIOLATION: Local tests must connect only to 127.0.0.1 or localhost. Found host: '${host}'.`);
    }

    const stagingRef = (process.env.ARCHSCALE_STAGING_PROJECT_REF || '').toLowerCase().trim();
    if (stagingRef) {
        if (host.includes(stagingRef) || parsed.username.toLowerCase().includes(stagingRef)) {
            throw new Error(`SECURITY VIOLATION: ARCHSCALE_TEST_DB_URL matches staging project ref '${stagingRef}'. Refusing to run.`);
        }
    }

    return parsed;
}

function createRuntimePool(): pg.Pool {
    if (process.env.NODE_ENV === 'test') {
        // Local test mode: strictly must NOT read ARCHSCALE_RUNTIME_DB_URL
        const testDbUrl = process.env.ARCHSCALE_TEST_DB_URL;
        const parsed = assertLocalTestDatabaseGuard(testDbUrl);
        return new Pool({
            host: parsed.hostname,
            port: parseInt(parsed.port || '5432', 10),
            user: 'archscale_app_runtime',
            password: 'archscale_runtime_local_pass',
            database: parsed.pathname.replace('/', '') || 'postgres',
            max: 10,
            idleTimeoutMillis: 30000,
            connectionTimeoutMillis: 10000
        });
    }

    // Staging / Production mode: connects strictly via ARCHSCALE_RUNTIME_DB_URL
    return new Pool({
        connectionString: config.archscaleRuntimeDbUrl,
        ssl: { rejectUnauthorized: false },
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 10000
    });
}

// Runtime pool connects strictly as archscale_app_runtime
// No superuser, no SET ROLE, no owner credentials.
export const runtimePool = createRuntimePool();

/**
 * Executes an application database operation within a single isolated transaction.
 * 
 * Invariant Guarantees:
 * 1. Transaction-Local Context: Executes `SELECT fn_set_app_context($1)` as the first statement.
 *    Because fn_set_app_context uses `set_config('archscale.current_context_id', ..., true)` (is_local = true),
 *    the GUC parameter is strictly scoped to this single transaction block.
 * 2. Session Pooler Safety: In Supabase session pooling mode (port 5432), server backends are pinned
 *    for the connection lifetime. `is_local = true` guarantees that upon `COMMIT` or `ROLLBACK`, the context
 *    GUC is automatically wiped, preventing context leakage between requests.
 * 3. Atomic Error Handling: Any exception automatically triggers a ROLLBACK before releasing the client.
 */
export async function withAppContext<T>(
    contextId: string,
    operation: (client: pg.PoolClient) => Promise<T>
): Promise<T> {
    const client = await runtimePool.connect();
    try {
        await client.query('BEGIN;');

        // Mandatory first statement: set and validate transaction-local security context
        await client.query('SELECT fn_set_app_context($1);', [contextId]);

        const result = await operation(client);

        await client.query('COMMIT;');
        return result;
    } catch (err) {
        await client.query('ROLLBACK;').catch(() => {});
        throw err;
    } finally {
        client.release();
    }
}

/**
 * Executes a transaction without a context (for pre-authentication queries like user mirror lookups).
 * Queries executed here see 0 tenant rows due to Row Level Security (RLS).
 */
export async function withAnonymousContext<T>(
    operation: (client: pg.PoolClient) => Promise<T>
): Promise<T> {
    const client = await runtimePool.connect();
    try {
        await client.query('BEGIN;');
        const result = await operation(client);
        await client.query('COMMIT;');
        return result;
    } catch (err) {
        await client.query('ROLLBACK;').catch(() => {});
        throw err;
    } finally {
        client.release();
    }
}
