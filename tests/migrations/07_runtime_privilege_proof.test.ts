import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase, RUNTIME_CONFIG } from '../setup/db_connection.js';
import pg from 'pg';

const { Pool } = pg;

describe('07_runtime_privilege_proof: Least-Privilege Role & Forged-Actor Defense', () => {
    let adminPool: pg.Pool;
    let runtimePool: pg.Pool;
    const testDb = 'test_db_07';

    beforeAll(async () => {
        adminPool = await createIsolatedTestDatabase(testDb);
        runtimePool = new Pool({
            ...RUNTIME_CONFIG,
            database: testDb
        });
    });

    afterAll(async () => {
        await runtimePool.end();
        await adminPool.end();
    });

    it('proves archscale_app_runtime has NO superuser, NO createdb, and NO bypassrls privileges', async () => {
        const res = await runtimePool.query<{
            rolsuper: boolean;
            rolcreaterole: boolean;
            rolcreatedb: boolean;
            rolbypassrls: boolean;
        }>(`
            SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls
            FROM pg_roles
            WHERE rolname = 'archscale_app_runtime';
        `);

        expect(res.rows[0].rolsuper).toBe(false);
        expect(res.rows[0].rolcreaterole).toBe(false);
        expect(res.rows[0].rolcreatedb).toBe(false);
        expect(res.rows[0].rolbypassrls).toBe(false);
    });

    it('proves archscale_app_runtime CANNOT execute DDL (schema modification rights revoked)', async () => {
        // Attempting to create a table as runtime role must be rejected by PostgreSQL permission check
        await expect(
            runtimePool.query('CREATE TABLE rogue_table (id int);')
        ).rejects.toThrow(/permission denied for schema public/);

        // Attempting to drop an existing table must be rejected
        await expect(
            runtimePool.query('DROP TABLE organisations CASCADE;')
        ).rejects.toThrow(/must be owner of table organisations/);
    });

    it('proves archscale_app_runtime CANNOT mutate audit_logs directly', async () => {
        // Insert audit log is allowed
        const ins = await runtimePool.query<{ id: string }>(
            `INSERT INTO audit_logs (action, target_entity, target_id)
             VALUES ('runtime.insert', 'audit', '1') RETURNING id;`
        );
        expect(ins.rows.length).toBe(1);

        // UPDATE permission is revoked
        await expect(
            runtimePool.query(`UPDATE audit_logs SET action = 'tampered' WHERE id = '${ins.rows[0].id}';`)
        ).rejects.toThrow(/permission denied for table audit_logs/);

        // DELETE permission is revoked
        await expect(
            runtimePool.query(`DELETE FROM audit_logs WHERE id = '${ins.rows[0].id}';`)
        ).rejects.toThrow(/permission denied for table audit_logs/);

        // TRUNCATE permission is revoked
        await expect(
            runtimePool.query('TRUNCATE TABLE audit_logs;')
        ).rejects.toThrow(/permission denied for table audit_logs/);
    });

    it('rejects forged-actor attempts on fn_approve_organisation (caller lacks founder standing)', async () => {
        // Setup org application
        const owner = (await adminPool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-FGD-OWN', 'fgdown@archscale.test') RETURNING id;"
        )).rows[0].id;

        const subOrg = (await adminPool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Forged Org', 'subscriber', 'studio_owner', 'APPLIED') RETURNING id;"
        )).rows[0].id;

        const req = (await adminPool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, justification)
             VALUES ('organisation', '${owner}', '${subOrg}', 'Forged onboarding') RETURNING id;`
        )).rows[0].id;

        // Create a non-founder user and membership (e.g. client_servicing or subscriber member)
        const csUser = (await adminPool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-FGD-CS', 'fgdcs@archscale.test') RETURNING id;"
        )).rows[0].id;

        const csMem = (await adminPool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status)
             VALUES ('${csUser}', '00000000-0000-0000-0000-000000000001', 'client_servicing', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        // Attacker attempts to call fn_approve_organisation passing client_servicing membership id
        await expect(
            runtimePool.query(
                `SELECT fn_approve_organisation(
                    '${req}',
                    '${csMem}',
                    'studio_owner',
                    ARRAY[]::text[],
                    '[]'::jsonb,
                    '${owner}',
                    'Forged approval'
                );`
            )
        ).rejects.toThrow(/Unauthorized: only an active platform founder can approve organisation onboarding/);

        // Attacker attempts passing a random / forged UUID that is not an active membership
        const randomId = '11111111-1111-1111-1111-111111111111';
        await expect(
            runtimePool.query(
                `SELECT fn_approve_organisation(
                    '${req}',
                    '${randomId}',
                    'studio_owner',
                    ARRAY[]::text[],
                    '[]'::jsonb,
                    '${owner}',
                    'Forged approval'
                );`
            )
        ).rejects.toThrow(/Acting membership 11111111-1111-1111-1111-111111111111 is not found or not active/);
    });

    it('rejects forged-actor attempts on fn_approve_membership (cross-org scope violation)', async () => {
        // Setup two distinct subscriber organisations
        const org1 = (await adminPool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Org Scope 1', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        const org2 = (await adminPool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Org Scope 2', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        const ownerUser1 = (await adminPool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-FGD-BO1', 'fgdbo1@archscale.test') RETURNING id;"
        )).rows[0].id;

        const ownerMem1 = (await adminPool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status)
             VALUES ('${ownerUser1}', '${org1}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        const applicantUser2 = (await adminPool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-FGD-APP2', 'fgdapp2@archscale.test') RETURNING id;"
        )).rows[0].id;

        const reqOrg2 = (await adminPool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification)
             VALUES ('membership', '${applicantUser2}', '${org2}', 'leader', 'Requesting role in Org 2') RETURNING id;`
        )).rows[0].id;

        // Owner from Org 1 attempts to approve request in Org 2 -> Scope violation rejected
        await expect(
            runtimePool.query(
                `SELECT fn_approve_membership('${reqOrg2}', '${ownerMem1}', 'Cross-tenant rogue approval');`
            )
        ).rejects.toThrow(/Scope violation: approver organisation .* does not match request organisation/);
    });
});
