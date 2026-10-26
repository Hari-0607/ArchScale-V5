import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase } from '../setup/db_connection.js';
import pg from 'pg';

describe('02_invariants_enforcement: Security Invariants on Real PostgreSQL', () => {
    let pool: pg.Pool;

    beforeAll(async () => {
        pool = await createIsolatedTestDatabase('test_db_02');
    });

    afterAll(async () => {
        await pool.end();
    });

    it('enforces separation of duties: approver cannot approve their own request', async () => {
        const user = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-SOD', 'sod@archscale.test') RETURNING id;"
        )).rows[0].id;

        const org = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('SOD Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        const membership = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${user}', '${org}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        const req = (await pool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification)
             VALUES ('membership', '${user}', '${org}', 'leader', 'Self promotion attempt') RETURNING id;`
        )).rows[0].id;

        // Approving own request via approval_steps must be rejected by trigger
        await expect(
            pool.query(
                `INSERT INTO approval_steps (request_id, step_number, required_role_key, decided_by, decision, reason)
                 VALUES ('${req}', 1, 'business_owner', '${membership}', 'APPROVED', 'Approving self');`
            )
        ).rejects.toThrow(/Separation of duties violation: approver .* cannot approve their own request/);
    });

    it('enforces level ceiling: approver level must be strictly greater than target role level', async () => {
        const userLeader = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-LDR', 'ldr@archscale.test') RETURNING id;"
        )).rows[0].id;

        const userCandidate = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-CND', 'cnd@archscale.test') RETURNING id;"
        )).rows[0].id;

        const org = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Level Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        // Leader has level 60
        const leaderMembership = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${userLeader}', '${org}', 'leader', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        // Candidate requests business_owner (level 80)
        const reqBO = (await pool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification)
             VALUES ('membership', '${userCandidate}', '${org}', 'business_owner', 'Want to be owner') RETURNING id;`
        )).rows[0].id;

        // Leader (60) attempting to approve Business Owner (80) must fail level ceiling
        await expect(
            pool.query(
                `INSERT INTO approval_steps (request_id, step_number, required_role_key, decided_by, decision, reason)
                 VALUES ('${reqBO}', 1, 'leader', '${leaderMembership}', 'APPROVED', 'Promoting to owner');`
            )
        ).rejects.toThrow(/Level ceiling violation: approver level \(60\) must be strictly greater than target role level \(80\)/);

        // Candidate requests another Leader (level 60)
        const reqLeader = (await pool.query<{ id: string }>(
            `INSERT INTO access_requests (request_type, requester_user_id, organisation_id, target_role_key, justification)
             VALUES ('membership', '${userCandidate}', '${org}', 'leader', 'Want to be peer leader') RETURNING id;`
        )).rows[0].id;

        // Leader (60) attempting to approve another Leader (60) must fail (strictly greater required)
        await expect(
            pool.query(
                `INSERT INTO approval_steps (request_id, step_number, required_role_key, decided_by, decision, reason)
                 VALUES ('${reqLeader}', 1, 'leader', '${leaderMembership}', 'APPROVED', 'Peer approval attempt');`
            )
        ).rejects.toThrow(/Level ceiling violation: approver level \(60\) must be strictly greater than target role level \(60\)/);
    });

    it('enforces expiry date requirement on roles where role.expiry_required = true', async () => {
        const user = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-INT', 'intern@archscale.test') RETURNING id;"
        )).rows[0].id;

        const org = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Intern Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        // Attempting to create an intern membership with NULL expires_at must fail
        await expect(
            pool.query(
                `INSERT INTO memberships (user_id, organisation_id, role_key, status, expires_at)
                 VALUES ('${user}', '${org}', 'intern', 'PENDING_APPROVAL', NULL);`
            )
        ).rejects.toThrow(/Membership for role intern requires an expiration date/);

        // Providing an expiry date succeeds
        const validIntern = await pool.query(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status, expires_at)
             VALUES ('${user}', '${org}', 'intern', 'PENDING_APPROVAL', now() + interval '90 days') RETURNING id;`
        );
        expect(validIntern.rows.length).toBe(1);
    });

    it('blocks activating membership if parent organisation is not ACTIVE', async () => {
        const user = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-PEND', 'pend@archscale.test') RETURNING id;"
        )).rows[0].id;

        // Org in APPLIED status
        const orgApplied = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Applied Studio', 'subscriber', 'studio_owner', 'APPLIED') RETURNING id;"
        )).rows[0].id;

        // Attempting to set membership status = 'ACTIVE' under non-ACTIVE org must fail
        await expect(
            pool.query(
                `INSERT INTO memberships (user_id, organisation_id, role_key, status)
                 VALUES ('${user}', '${orgApplied}', 'business_owner', 'ACTIVE');`
            )
        ).rejects.toThrow(/parent organisation is in APPLIED status \(must be ACTIVE\)/);
    });

    it('protects last active founder and last active business_owner from removal or suspension while org is active', async () => {
        // Platform Org was seeded with id '00000000-0000-0000-0000-000000000001'
        const founderUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-FNDR', 'founder@archscale.test') RETURNING id;"
        )).rows[0].id;

        const founderMembership = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status)
             VALUES ('${founderUser}', '00000000-0000-0000-0000-000000000001', 'founder', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        // Attempting to suspend the only active founder must be rejected
        await expect(
            pool.query(`UPDATE memberships SET status = 'SUSPENDED' WHERE id = '${founderMembership}';`)
        ).rejects.toThrow(/Cannot remove or suspend the last active founder of an active platform organisation/);

        // Attempting to delete the only active founder must be rejected
        await expect(
            pool.query(`DELETE FROM memberships WHERE id = '${founderMembership}';`)
        ).rejects.toThrow(/Cannot remove or suspend the last active founder of an active platform organisation/);

        // Same for business_owner in an active subscriber org
        const ownerUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-BO1', 'bo1@archscale.test') RETURNING id;"
        )).rows[0].id;

        const subOrg = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Owner Prot Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        const ownerMembership = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status)
             VALUES ('${ownerUser}', '${subOrg}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        await expect(
            pool.query(`UPDATE memberships SET status = 'SUSPENDED' WHERE id = '${ownerMembership}';`)
        ).rejects.toThrow(/Cannot remove or suspend the last active business_owner of an active subscriber organisation/);
    });

    it('enforces support_access_grants invariants: platform staff, subscriber target, 24h cap, reason required', async () => {
        const staffUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-STF', 'staff@archscale.test') RETURNING id;"
        )).rows[0].id;

        const staffMembership = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status)
             VALUES ('${staffUser}', '00000000-0000-0000-0000-000000000001', 'client_servicing', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        const subOrg = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Support Target Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        // 1. Valid grant capped at 24 hours succeeds
        const validGrant = await pool.query(
            `INSERT INTO support_access_grants (staff_membership_id, target_organisation_id, reason, expires_at)
             VALUES ('${staffMembership}', '${subOrg}', 'Investigating drawing sync issue', now() + interval '8 hours') RETURNING id;`
        );
        expect(validGrant.rows.length).toBe(1);

        // 2. Exceeding 24 hours fails check constraint
        await expect(
            pool.query(
                `INSERT INTO support_access_grants (staff_membership_id, target_organisation_id, reason, expires_at)
                 VALUES ('${staffMembership}', '${subOrg}', 'Investigating issue', now() + interval '72 hours');`
            )
        ).rejects.toThrow(/chk_support_grant_max_24h/);

        // 3. Subscriber member attempting to act as support staff fails trigger
        const tenantUser = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-TNT', 'tenant@archscale.test') RETURNING id;"
        )).rows[0].id;

        const tenantMembership = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status)
             VALUES ('${tenantUser}', '${subOrg}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        await expect(
            pool.query(
                `INSERT INTO support_access_grants (staff_membership_id, target_organisation_id, reason, expires_at)
                 VALUES ('${tenantMembership}', '${subOrg}', 'Rogue support grant', now() + interval '4 hours');`
            )
        ).rejects.toThrow(/must belong to the platform organisation/);
    });
});
