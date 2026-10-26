import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase } from '../setup/db_connection.js';
import pg from 'pg';

describe('03_org_status_cascade: Lifecycle Cascade & Suspension Exemption', () => {
    let pool: pg.Pool;

    beforeAll(async () => {
        pool = await createIsolatedTestDatabase('test_db_03');
    });

    afterAll(async () => {
        await pool.end();
    });

    it('suspending an organisation revokes all contexts and suspends memberships in the same transaction', async () => {
        const user1 = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-CAS1', 'cas1@archscale.test') RETURNING id;"
        )).rows[0].id;
        const user2 = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-CAS2', 'cas2@archscale.test') RETURNING id;"
        )).rows[0].id;

        const org = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Cascade Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        const ws = (await pool.query<{ id: string }>(
            `INSERT INTO workspaces (organisation_id, name) VALUES ('${org}', 'Main WS') RETURNING id;`
        )).rows[0].id;

        const mem1 = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${user1}', '${org}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        const mem2 = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${user2}', '${org}', 'leader', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        const ctx1 = (await pool.query<{ id: string }>(
            `INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at)
             VALUES ('${user1}', 's1', '${org}', '${ws}', '${mem1}', now() + interval '8 hours') RETURNING id;`
        )).rows[0].id;

        const ctx2 = (await pool.query<{ id: string }>(
            `INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at)
             VALUES ('${user2}', 's2', '${org}', '${ws}', '${mem2}', now() + interval '8 hours') RETURNING id;`
        )).rows[0].id;

        // Contexts are valid initially
        expect((await pool.query<{ is_context_valid: boolean }>(`SELECT is_context_valid('${ctx1}') as is_context_valid;`)).rows[0].is_context_valid).toBe(true);
        expect((await pool.query<{ is_context_valid: boolean }>(`SELECT is_context_valid('${ctx2}') as is_context_valid;`)).rows[0].is_context_valid).toBe(true);

        // Suspend organisation
        await pool.query(`UPDATE organisations SET status = 'SUSPENDED' WHERE id = '${org}';`);

        // Check 1: All active contexts for this org are revoked
        const contexts = await pool.query<{ id: string; revoked_at: Date | null }>(
            `SELECT id, revoked_at FROM access_contexts WHERE organisation_id = '${org}';`
        );
        expect(contexts.rows.every(c => c.revoked_at !== null)).toBe(true);

        // Check 2: All memberships for this org are now SUSPENDED
        const memberships = await pool.query<{ id: string; status: string }>(
            `SELECT id, status FROM memberships WHERE organisation_id = '${org}';`
        );
        expect(memberships.rows.every(m => m.status === 'SUSPENDED')).toBe(true);

        // Check 3: is_context_valid returns false
        expect((await pool.query<{ is_context_valid: boolean }>(`SELECT is_context_valid('${ctx1}') as is_context_valid;`)).rows[0].is_context_valid).toBe(false);
        expect((await pool.query<{ is_context_valid: boolean }>(`SELECT is_context_valid('${ctx2}') as is_context_valid;`)).rows[0].is_context_valid).toBe(false);
    });

    it('tests the suspension-exemption case vs the blocked case for custodian protection', async () => {
        const user = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-EXMP', 'exmp@archscale.test') RETURNING id;"
        )).rows[0].id;

        const org = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Exempt Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        const ownerMem = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${user}', '${org}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        // Blocked Case: Directly suspending the last business_owner while org is ACTIVE fails
        await expect(
            pool.query(`UPDATE memberships SET status = 'SUSPENDED' WHERE id = '${ownerMem}';`)
        ).rejects.toThrow(/Cannot remove or suspend the last active business_owner/);

        // Exempt Case: Suspending the parent organisation triggers cascading membership suspension,
        // and the custodian protection trigger allows it because parent org status is SUSPENDED.
        await expect(
            pool.query(`UPDATE organisations SET status = 'SUSPENDED' WHERE id = '${org}';`)
        ).resolves.toBeDefined();

        // Verify membership is now SUSPENDED without trigger failure
        const memStatus = await pool.query<{ status: string }>(
            `SELECT status FROM memberships WHERE id = '${ownerMem}';`
        );
        expect(memStatus.rows[0].status).toBe('SUSPENDED');
    });
});
