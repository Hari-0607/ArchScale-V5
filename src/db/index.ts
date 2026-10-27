import pg from 'pg';
import { config } from '../config/env.js';

const { Pool } = pg;

// Runtime pool connects strictly as archscale_app_runtime via ARCHSCALE_RUNTIME_DB_URL
// No superuser, no SET ROLE, no owner credentials.
export const runtimePool = new Pool({
    connectionString: config.archscaleRuntimeDbUrl,
    ssl: { rejectUnauthorized: false },
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

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
