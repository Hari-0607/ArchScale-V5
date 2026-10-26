import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase } from '../setup/db_connection.js';
import pg from 'pg';

describe('04_atomic_approvals: Transactional Functions Atomicity & Clean Rollbacks', () => {
    let pool: pg.Pool;

    beforeAll(async () => {
        pool = await createIsolatedTestDatabase('test_db_04');
    });

    afterAll(async () => {
        await pool.end();
    });

    it('fn_approve_organisation executes atomically: org active, entitlements, seats, owner membership, audit log', async () => {
        // Platform Founder setup
        const founderUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-F1', 'f1@archscale.test') RETURNING id;"
        )).rows[0].id;
        const founderMem = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status)
             VALUES ('${founderUser}', '00000000-0000-0000-0000-000000000001', 'founder', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        // Prospective Business Owner
        const ownerUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-OWN1', 'own1@archscale.test') RETURNING id;"
        )).rows[0].id;

        // Ecosystem apps
        await pool.query(
            "INSERT INTO app_catalogue (app_key, name) VALUES ('app_modeler', 'Arch Modeler') ON CONFLICT DO NOTHING;"
        );

        // Client Servicing sets up APPLIED org and request
        const appliedOrg = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Zenith Arch', 'subscriber', 'studio_owner', 'APPLIED') RETURNING id;"
        )).rows[0].id;

        const orgReq = (await pool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, justification, requested_apps)
             VALUES ('organisation', '${ownerUser}', '${appliedOrg}', 'Onboarding new enterprise design studio', ARRAY['app_modeler']) RETURNING id;`
        )).rows[0].id;

        const seatConfig = JSON.stringify([
            { app_key: 'app_modeler', role_key: 'business_owner', seat_limit: 2 },
            { app_key: 'app_modeler', role_key: 'leader', seat_limit: 5 }
        ]);

        // Run fn_approve_organisation
        const approvedOrgId = (await pool.query<{ fn_approve_organisation: string }>(
            `SELECT fn_approve_organisation(
                '${orgReq}',
                '${founderMem}',
                'studio_owner',
                ARRAY['app_modeler'],
                '${seatConfig}'::jsonb,
                '${ownerUser}',
                'Approved following contract verification'
            );`
        )).rows[0].fn_approve_organisation;

        expect(approvedOrgId).toBe(appliedOrg);

        // 1. Organisation is ACTIVE
        const orgRes = await pool.query<{ status: string; reviewed_by: string }>(
            `SELECT status, reviewed_by FROM organisations WHERE id = '${appliedOrg}';`
        );
        expect(orgRes.rows[0].status).toBe('ACTIVE');
        expect(orgRes.rows[0].reviewed_by).toBe(founderUser);

        // 2. Entitlement exists
        const entRes = await pool.query<{ is_enabled: boolean }>(
            `SELECT is_enabled FROM organisation_entitlements WHERE organisation_id = '${appliedOrg}' AND app_key = 'app_modeler';`
        );
        expect(entRes.rows[0].is_enabled).toBe(true);

        // 3. Seats allocated for business_owner (1 allocated)
        const seatRes = await pool.query<{ seat_limit: number; allocated_seats: number }>(
            `SELECT seat_limit, allocated_seats FROM organisation_seats WHERE organisation_id = '${appliedOrg}' AND app_key = 'app_modeler' AND role_key = 'business_owner';`
        );
        expect(seatRes.rows[0].seat_limit).toBe(2);
        expect(seatRes.rows[0].allocated_seats).toBe(1);

        // 4. Owner membership is ACTIVE with primary owner flag
        const memRes = await pool.query<{ status: string; is_primary_owner: boolean }>(
            `SELECT status, is_primary_owner FROM memberships WHERE user_id = '${ownerUser}' AND organisation_id = '${appliedOrg}';`
        );
        expect(memRes.rows[0].status).toBe('ACTIVE');
        expect(memRes.rows[0].is_primary_owner).toBe(true);

        // 5. Audit log entry written
        const auditRes = await pool.query<{ action: string; target_id: string }>(
            `SELECT action, target_id FROM audit_logs WHERE organisation_id = '${appliedOrg}' AND action = 'organisation.approve';`
        );
        expect(auditRes.rows.length).toBe(1);
    });

    it('partial failure in fn_approve_organisation rolls back cleanly with zero leftover state', async () => {
        const founderUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-F2', 'f2@archscale.test') RETURNING id;"
        )).rows[0].id;
        const founderMem = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status)
             VALUES ('${founderUser}', '00000000-0000-0000-0000-000000000001', 'founder', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        const ownerUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-OWN2', 'own2@archscale.test') RETURNING id;"
        )).rows[0].id;

        const appliedOrg = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Rollback Studio', 'subscriber', 'studio_owner', 'APPLIED') RETURNING id;"
        )).rows[0].id;

        const orgReq = (await pool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, justification)
             VALUES ('organisation', '${ownerUser}', '${appliedOrg}', 'Rollback test request') RETURNING id;`
        )).rows[0].id;

        // Pass invalid tenant type to trigger error inside function
        await expect(
            pool.query(
                `SELECT fn_approve_organisation(
                    '${orgReq}',
                    '${founderMem}',
                    'non_existent_tenant_type',
                    ARRAY['app_modeler'],
                    '[]'::jsonb,
                    '${ownerUser}',
                    'Should fail'
                );`
            )
        ).rejects.toThrow(/Tenant type non_existent_tenant_type is invalid/);

        // Assert org remains in APPLIED status
        const orgRes = await pool.query<{ status: string }>(
            `SELECT status FROM organisations WHERE id = '${appliedOrg}';`
        );
        expect(orgRes.rows[0].status).toBe('APPLIED');

        // Assert no owner membership was created
        const memRes = await pool.query(
            `SELECT id FROM memberships WHERE user_id = '${ownerUser}' AND organisation_id = '${appliedOrg}';`
        );
        expect(memRes.rows.length).toBe(0);

        // Assert request remains PENDING
        const reqRes = await pool.query<{ status: string }>(
            `SELECT status FROM access_requests WHERE id = '${orgReq}';`
        );
        expect(reqRes.rows[0].status).toBe('PENDING');
    });

    it('fn_approve_membership executes atomically: checks seats, updates seats, activates member, writes audit', async () => {
        // Setup org, app, seats, owner, requester
        const org = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Approval Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        await pool.query("INSERT INTO app_catalogue (app_key, name) VALUES ('app_draft', 'Arch Draft') ON CONFLICT DO NOTHING;");

        // 1 seat for leader
        await pool.query(
            `INSERT INTO organisation_seats (organisation_id, app_key, role_key, seat_limit, allocated_seats)
             VALUES ('${org}', 'app_draft', 'leader', 1, 0);`
        );

        const ownerUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-BO-AP', 'boap@archscale.test') RETURNING id;"
        )).rows[0].id;

        const ownerMem = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status)
             VALUES ('${ownerUser}', '${org}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        const candUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-LDR-AP', 'ldrap@archscale.test') RETURNING id;"
        )).rows[0].id;

        const req = (await pool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification, requested_apps)
             VALUES ('membership', '${candUser}', '${org}', 'leader', 'Requesting project leader role', ARRAY['app_draft']) RETURNING id;`
        )).rows[0].id;

        // Approve membership
        const memId = (await pool.query<{ fn_approve_membership: string }>(
            `SELECT fn_approve_membership('${req}', '${ownerMem}', 'Promoted to project lead');`
        )).rows[0].fn_approve_membership;

        // 1. Membership is ACTIVE with leader role
        const memRes = await pool.query<{ status: string; role_key: string }>(
            `SELECT status, role_key FROM memberships WHERE id = '${memId}';`
        );
        expect(memRes.rows[0].status).toBe('ACTIVE');
        expect(memRes.rows[0].role_key).toBe('leader');

        // 2. Allocated seats incremented to 1
        const seatRes = await pool.query<{ allocated_seats: number }>(
            `SELECT allocated_seats FROM organisation_seats WHERE organisation_id = '${org}' AND app_key = 'app_draft' AND role_key = 'leader';`
        );
        expect(seatRes.rows[0].allocated_seats).toBe(1);

        // 3. membership_seats contains binding
        const memSeatRes = await pool.query(
            `SELECT * FROM membership_seats WHERE membership_id = '${memId}' AND app_key = 'app_draft';`
        );
        expect(memSeatRes.rows.length).toBe(1);

        // 4. Audit log recorded
        const auditRes = await pool.query(
            `SELECT * FROM audit_logs WHERE organisation_id = '${org}' AND action = 'membership.approve';`
        );
        expect(auditRes.rows.length).toBe(1);
    });
});
