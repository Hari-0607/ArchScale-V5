import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase } from '../setup/db_connection.js';
import pg from 'pg';

describe('05_concurrent_seats_race: Concurrent Seat Race & Reconciliation Test', () => {
    let pool: pg.Pool;

    beforeAll(async () => {
        pool = await createIsolatedTestDatabase('test_db_05');
    });

    afterAll(async () => {
        await pool.end();
    });

    it('two simultaneous approvals for the last available seat: exactly one succeeds, one fails, leaving no over-allocation', async () => {
        const org = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Race Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        await pool.query("INSERT INTO app_catalogue (app_key, name) VALUES ('app_race', 'Race App') ON CONFLICT DO NOTHING;");

        // Exactly 1 seat limit, 0 allocated
        await pool.query(
            `INSERT INTO organisation_seats (organisation_id, app_key, role_key, seat_limit, allocated_seats)
             VALUES ('${org}', 'app_race', 'leader', 1, 0);`
        );

        const ownerUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-BO-RACE', 'borace@archscale.test') RETURNING id;"
        )).rows[0].id;

        const ownerMem = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status)
             VALUES ('${ownerUser}', '${org}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        // User A and User B both request the single available leader seat
        const userA = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-A', 'usera@archscale.test') RETURNING id;"
        )).rows[0].id;
        const userB = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-B', 'userb@archscale.test') RETURNING id;"
        )).rows[0].id;

        const reqA = (await pool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification, requested_apps)
             VALUES ('membership', '${userA}', '${org}', 'leader', 'User A lead', ARRAY['app_race']) RETURNING id;`
        )).rows[0].id;

        const reqB = (await pool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification, requested_apps)
             VALUES ('membership', '${userB}', '${org}', 'leader', 'User B lead', ARRAY['app_race']) RETURNING id;`
        )).rows[0].id;

        // Launch both approvals concurrently in separate database connections
        const promiseA = pool.query(`SELECT fn_approve_membership('${reqA}', '${ownerMem}', 'Approving A');`);
        const promiseB = pool.query(`SELECT fn_approve_membership('${reqB}', '${ownerMem}', 'Approving B');`);

        const results = await Promise.allSettled([promiseA, promiseB]);

        const fulfilled = results.filter(r => r.status === 'fulfilled');
        const rejected = results.filter(r => r.status === 'rejected');

        // Exactly one approval must succeed, exactly one must fail with seat capacity exceeded
        expect(fulfilled.length).toBe(1);
        expect(rejected.length).toBe(1);

        const rejectionError = (rejected[0] as PromiseRejectedResult).reason;
        expect(rejectionError.message).toMatch(/Seat capacity exceeded for app app_race and role leader/);

        // Verify allocated_seats is exactly 1 (not 2)
        const seatRes = await pool.query<{ allocated_seats: number; seat_limit: number }>(
            `SELECT allocated_seats, seat_limit FROM organisation_seats WHERE organisation_id = '${org}' AND app_key = 'app_race' AND role_key = 'leader';`
        );
        expect(seatRes.rows[0].allocated_seats).toBe(1);
        expect(seatRes.rows[0].allocated_seats).toBeLessThanOrEqual(seatRes.rows[0].seat_limit);
    });

    it('reconciles allocated_seats count against actual active rows in membership_seats', async () => {
        const org = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Recon Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        await pool.query("INSERT INTO app_catalogue (app_key, name) VALUES ('app_recon', 'Recon App') ON CONFLICT DO NOTHING;");

        // Limit: 5, Allocated: 3
        await pool.query(
            `INSERT INTO organisation_seats (organisation_id, app_key, role_key, seat_limit, allocated_seats)
             VALUES ('${org}', 'app_recon', 'leader', 5, 0);`
        );

        const ownerUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-BO-REC', 'borec@archscale.test') RETURNING id;"
        )).rows[0].id;

        const ownerMem = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status)
             VALUES ('${ownerUser}', '${org}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        // Approve 3 distinct members
        for (let i = 1; i <= 3; i++) {
            const u = (await pool.query<{ id: string }>(
                `INSERT INTO users (user_code, email) VALUES ('USR-REC-${i}', 'rec${i}@archscale.test') RETURNING id;`
            )).rows[0].id;

            const r = (await pool.query<{ id: string }>(
                `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification, requested_apps)
                 VALUES ('membership', '${u}', '${org}', 'leader', 'Rec Member', ARRAY['app_recon']) RETURNING id;`
            )).rows[0].id;

            await pool.query(`SELECT fn_approve_membership('${r}', '${ownerMem}', 'Approved');`);
        }

        // Run SQL Reconciliation Check: allocated_seats in organisation_seats == count of active membership_seats
        const reconciliation = await pool.query<{
            recorded_allocation: number;
            actual_active_membership_seats: number;
        }>(`
            SELECT 
                os.allocated_seats as recorded_allocation,
                COUNT(ms.app_key)::int as actual_active_membership_seats
            FROM organisation_seats os
            LEFT JOIN memberships m ON m.organisation_id = os.organisation_id AND m.role_key = os.role_key AND m.status = 'ACTIVE'
            LEFT JOIN membership_seats ms ON ms.membership_id = m.id AND ms.app_key = os.app_key
            WHERE os.organisation_id = '${org}' AND os.app_key = 'app_recon' AND os.role_key = 'leader'
            GROUP BY os.allocated_seats;
        `);

        expect(reconciliation.rows[0].recorded_allocation).toBe(3);
        expect(reconciliation.rows[0].actual_active_membership_seats).toBe(3);
        expect(reconciliation.rows[0].recorded_allocation).toBe(reconciliation.rows[0].actual_active_membership_seats);
    });
});
