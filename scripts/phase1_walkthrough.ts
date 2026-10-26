import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase } from '../tests/setup/db_connection.js';
import pg from 'pg';

describe('Phase 1 Walkthrough: End-to-End Lifecycle & Atomic Failure Proving', () => {
    let pool: pg.Pool;

    beforeAll(async () => {
        pool = await createIsolatedTestDatabase('test_db_walkthrough');
    });

    afterAll(async () => {
        await pool.end();
    });

    it('executes full happy-path lifecycle and deliberately failing seat-exhaustion variant', async () => {
        console.log('\n--- [Step 1: Setup Platform Founder & Ecosystem App] ---');
        const founderUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-FNDR-WT', 'founder.wt@archscale.test') RETURNING id;"
        )).rows[0].id;

        const founderMem = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status)
             VALUES ('${founderUser}', '00000000-0000-0000-0000-000000000001', 'founder', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        await pool.query(
            "INSERT INTO app_catalogue (app_key, name) VALUES ('app_bim', 'ArchScale BIM Studio') ON CONFLICT DO NOTHING;"
        );

        console.log('--- [Step 2: Client Servicing Submits APPLIED Organisation & Request] ---');
        const ownerUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-OWNER-WT', 'owner.wt@archscale.test') RETURNING id;"
        )).rows[0].id;

        const org = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Metropolis Architects', 'subscriber', 'studio_owner', 'APPLIED') RETURNING id;"
        )).rows[0].id;

        const orgReq = (await pool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, justification, requested_apps)
             VALUES ('organisation', '${ownerUser}', '${org}', 'Enterprise onboarding', ARRAY['app_bim']) RETURNING id;`
        )).rows[0].id;

        // Seat capacity: 2 business owners, 1 leader, 1 intern
        const seatLimits = JSON.stringify([
            { app_key: 'app_bim', role_key: 'business_owner', seat_limit: 2 },
            { app_key: 'app_bim', role_key: 'leader', seat_limit: 1 },
            { app_key: 'app_bim', role_key: 'intern', seat_limit: 1 }
        ]);

        console.log('--- [Step 3: Founder Approves Organisation via fn_approve_organisation] ---');
        await pool.query(
            `SELECT fn_approve_organisation(
                '${orgReq}',
                '${founderMem}',
                'studio_owner',
                ARRAY['app_bim'],
                '${seatLimits}'::jsonb,
                '${ownerUser}',
                'Board approved onboarding'
            );`
        );

        const orgCheck = await pool.query<{ status: string }>(`SELECT status FROM organisations WHERE id = '${org}';`);
        expect(orgCheck.rows[0].status).toBe('ACTIVE');

        const ownerMem = (await pool.query<{ id: string }>(
            `SELECT id FROM memberships WHERE user_id = '${ownerUser}' AND organisation_id = '${org}';`
        )).rows[0].id;

        console.log('--- [Step 4: Business Owner Approves Leader] ---');
        const leaderUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-LEAD-WT', 'leader.wt@archscale.test') RETURNING id;"
        )).rows[0].id;

        const leaderReq = (await pool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification, requested_apps)
             VALUES ('membership', '${leaderUser}', '${org}', 'leader', 'Lead Project Alpha', ARRAY['app_bim']) RETURNING id;`
        )).rows[0].id;

        const leaderMem = (await pool.query<{ fn_approve_membership: string }>(
            `SELECT fn_approve_membership('${leaderReq}', '${ownerMem}', 'Approved by owner');`
        )).rows[0].fn_approve_membership;

        const leaderCheck = await pool.query<{ status: string }>(`SELECT status FROM memberships WHERE id = '${leaderMem}';`);
        expect(leaderCheck.rows[0].status).toBe('ACTIVE');

        console.log('--- [Step 5: Business Owner Approves Intern with Required Expiry] ---');
        const internUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-INT-WT', 'intern.wt@archscale.test') RETURNING id;"
        )).rows[0].id;

        const internReq = (await pool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification, requested_apps, requested_duration)
             VALUES ('membership', '${internUser}', '${org}', 'intern', 'Design intern summer program', ARRAY['app_bim'], interval '90 days') RETURNING id;`
        )).rows[0].id;

        const internMem = (await pool.query<{ fn_approve_membership: string }>(
            `SELECT fn_approve_membership('${internReq}', '${ownerMem}', 'Approved for 90 days');`
        )).rows[0].fn_approve_membership;

        const internCheck = await pool.query<{ status: string; expires_at: Date | null }>(
            `SELECT status, expires_at FROM memberships WHERE id = '${internMem}';`
        );
        expect(internCheck.rows[0].status).toBe('ACTIVE');
        expect(internCheck.rows[0].expires_at).not.toBeNull();

        console.log('--- [Step 6: Check Seat Accounting and Audit Entries] ---');
        const seats = await pool.query<{ role_key: string; allocated_seats: number; seat_limit: number }>(
            `SELECT role_key, allocated_seats, seat_limit FROM organisation_seats WHERE organisation_id = '${org}' ORDER BY role_key;`
        );
        console.table(seats.rows);
        expect(seats.rows.find(s => s.role_key === 'business_owner')?.allocated_seats).toBe(1);
        expect(seats.rows.find(s => s.role_key === 'leader')?.allocated_seats).toBe(1);
        expect(seats.rows.find(s => s.role_key === 'intern')?.allocated_seats).toBe(1);

        const auditEntries = await pool.query<{ action: string; target_entity: string }>(
            `SELECT action, target_entity FROM audit_logs WHERE organisation_id = '${org}';`
        );
        expect(auditEntries.rows.length).toBeGreaterThanOrEqual(3);

        console.log('--- [Step 7: Deliberately Failing Variant: Intern Requested with No Seats Left] ---');
        // We already allocated 1/1 intern seats. Another candidate requests the intern seat:
        const rogueUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-ROGUE-WT', 'rogue.wt@archscale.test') RETURNING id;"
        )).rows[0].id;

        const rogueReq = (await pool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification, requested_apps, requested_duration)
             VALUES ('membership', '${rogueUser}', '${org}', 'intern', 'Over-seat intern', ARRAY['app_bim'], interval '30 days') RETURNING id;`
        )).rows[0].id;

        // Must fail atomic seat check under FOR UPDATE
        await expect(
            pool.query(`SELECT fn_approve_membership('${rogueReq}', '${ownerMem}', 'Should fail');`)
        ).rejects.toThrow(/Seat capacity exceeded for app app_bim and role intern: limit is 1, allocated is 1/);

        // Prove no partial data remains: rogueUser has zero memberships and request is still PENDING
        const rogueMemCheck = await pool.query(`SELECT * FROM memberships WHERE user_id = '${rogueUser}';`);
        expect(rogueMemCheck.rows.length).toBe(0);

        const rogueReqCheck = await pool.query<{ status: string }>(`SELECT status FROM access_requests WHERE id = '${rogueReq}';`);
        expect(rogueReqCheck.rows[0].status).toBe('PENDING');

        console.log('--- [Step 8: Suspend Organisation and Verify Cascade] ---');
        // Create an access context for the leader first
        const wsId = (await pool.query<{ id: string }>(`SELECT id FROM workspaces WHERE organisation_id = '${org}' LIMIT 1;`)).rows[0].id;
        const ctxId = (await pool.query<{ id: string }>(
            `INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at)
             VALUES ('${leaderUser}', 'wt-sess-1', '${org}', '${wsId}', '${leaderMem}', now() + interval '12 hours') RETURNING id;`
        )).rows[0].id;

        expect((await pool.query<{ is_context_valid: boolean }>(`SELECT is_context_valid('${ctxId}') as is_context_valid;`)).rows[0].is_context_valid).toBe(true);

        // Suspend organisation
        await pool.query(`UPDATE organisations SET status = 'SUSPENDED' WHERE id = '${org}';`);

        // Check context is revoked
        expect((await pool.query<{ is_context_valid: boolean }>(`SELECT is_context_valid('${ctxId}') as is_context_valid;`)).rows[0].is_context_valid).toBe(false);

        // Check all memberships are now SUSPENDED
        const mems = await pool.query<{ status: string }>(`SELECT status FROM memberships WHERE organisation_id = '${org}';`);
        expect(mems.rows.every(m => m.status === 'SUSPENDED')).toBe(true);
        console.log('--- [Walkthrough Complete: All Assertions Verified] ---\n');
    });
});
