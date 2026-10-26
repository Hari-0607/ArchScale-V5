import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase } from '../setup/db_connection.js';
import pg from 'pg';

describe('01_schema_and_types: Core Schema & Invariants on Real PostgreSQL', () => {
    let pool: pg.Pool;

    beforeAll(async () => {
        pool = await createIsolatedTestDatabase('test_db_01');
    });

    afterAll(async () => {
        await pool.end();
    });

    it('enforces exactly ONE platform organisation via partial unique index', async () => {
        const result = await pool.query<{ count: string }>(
            "SELECT count(*)::text FROM organisations WHERE portal = 'platform';"
        );
        expect(parseInt(result.rows[0].count, 10)).toBe(1);

        // Attempting to insert a second platform org must be rejected by PostgreSQL unique index
        await expect(
            pool.query(
                "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Rogue Platform Org', 'platform', NULL, 'ACTIVE');"
            )
        ).rejects.toThrow(/idx_single_platform_org/);
    });

    it('enforces organisations.tenant_type_key is NULL iff portal = platform', async () => {
        // Platform org cannot have a tenant_type_key
        await expect(
            pool.query(
                "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Invalid Platform', 'platform', 'studio_owner', 'ACTIVE');"
            )
        ).rejects.toThrow(/chk_org_portal_tenant_type/);

        // Subscriber org MUST have a tenant_type_key
        await expect(
            pool.query(
                "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Invalid Subscriber', 'subscriber', NULL, 'ACTIVE');"
            )
        ).rejects.toThrow(/chk_org_portal_tenant_type/);

        // Valid subscriber org succeeds
        const insertSub = await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Studio A', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        );
        expect(insertSub.rows.length).toBe(1);
    });

    it('enforces users table as an identity mirror with NO roles/tenants and unique user_code', async () => {
        const user1 = await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-001', 'user1@archscale.test') RETURNING id;"
        );
        expect(user1.rows.length).toBe(1);

        // Duplicate user_code must fail
        await expect(
            pool.query("INSERT INTO users (user_code, email) VALUES ('USR-001', 'user2@archscale.test');")
        ).rejects.toThrow(/users_user_code_key/);

        // Duplicate email must fail
        await expect(
            pool.query("INSERT INTO users (user_code, email) VALUES ('USR-002', 'user1@archscale.test');")
        ).rejects.toThrow(/users_email_key/);
    });

    it('enforces seat accounting invariant: allocated_seats <= seat_limit', async () => {
        await pool.query(
            "INSERT INTO app_catalogue (app_key, name, description) VALUES ('app_canvas', 'Arch Canvas', 'CAD & BIM workspace') ON CONFLICT DO NOTHING;"
        );

        const orgRes = await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('BIM Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        );
        const orgId = orgRes.rows[0].id;

        // Inserting seats with limit 5, allocated 2 succeeds
        await pool.query(
            `INSERT INTO organisation_seats (organisation_id, app_key, role_key, seat_limit, allocated_seats)
             VALUES ('${orgId}', 'app_canvas', 'business_owner', 5, 2);`
        );

        // Updating allocated_seats to 6 (exceeding limit 5) must fail check constraint
        await expect(
            pool.query(
                `UPDATE organisation_seats SET allocated_seats = 6 WHERE organisation_id = '${orgId}' AND app_key = 'app_canvas';`
            )
        ).rejects.toThrow(/chk_seats_allocated_lte_limit/);
    });

    it('enforces access_contexts 24-hour lifetime hard check', async () => {
        const user = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-CTX', 'ctx@archscale.test') RETURNING id;"
        )).rows[0].id;

        const org = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Context Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        const workspace = (await pool.query<{ id: string }>(
            `INSERT INTO workspaces (organisation_id, name) VALUES ('${org}', 'Main Workspace') RETURNING id;`
        )).rows[0].id;

        const membership = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${user}', '${org}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        // Valid context with 12 hour expiry succeeds
        const validContext = await pool.query<{ id: string }>(
            `INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at)
             VALUES ('${user}', 'sess_valid', '${org}', '${workspace}', '${membership}', now() + interval '12 hours')
             RETURNING id;`
        );
        expect(validContext.rows.length).toBe(1);

        // Invalid context with 25 hour expiry fails check constraint
        await expect(
            pool.query(
                `INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at)
                 VALUES ('${user}', 'sess_invalid', '${org}', '${workspace}', '${membership}', now() + interval '25 hours');`
            )
        ).rejects.toThrow(/chk_context_max_24h/);
    });

    it('evaluates is_context_valid correctly across org and membership states', async () => {
        const user = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-VAL', 'val@archscale.test') RETURNING id;"
        )).rows[0].id;

        const org = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Validation Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        const workspace = (await pool.query<{ id: string }>(
            `INSERT INTO workspaces (organisation_id, name) VALUES ('${org}', 'Default Workspace') RETURNING id;`
        )).rows[0].id;

        const membership = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${user}', '${org}', 'leader', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        const context = (await pool.query<{ id: string }>(
            `INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at)
             VALUES ('${user}', 'sess_test', '${org}', '${workspace}', '${membership}', now() + interval '2 hours')
             RETURNING id;`
        )).rows[0].id;

        // 1. When ACTIVE: is_context_valid is TRUE
        const check1 = await pool.query<{ is_context_valid: boolean }>(
            `SELECT is_context_valid('${context}') as is_context_valid;`
        );
        expect(check1.rows[0].is_context_valid).toBe(true);

        // 2. When revoked: is_context_valid is FALSE
        await pool.query(`UPDATE access_contexts SET revoked_at = now() WHERE id = '${context}';`);
        const checkRevoked = await pool.query<{ is_context_valid: boolean }>(
            `SELECT is_context_valid('${context}') as is_context_valid;`
        );
        expect(checkRevoked.rows[0].is_context_valid).toBe(false);

        // Unrevoke
        await pool.query(`UPDATE access_contexts SET revoked_at = NULL WHERE id = '${context}';`);

        // 3. When membership is SUSPENDED: is_context_valid is FALSE
        await pool.query(`UPDATE memberships SET status = 'SUSPENDED' WHERE id = '${membership}';`);
        const checkMemSuspended = await pool.query<{ is_context_valid: boolean }>(
            `SELECT is_context_valid('${context}') as is_context_valid;`
        );
        expect(checkMemSuspended.rows[0].is_context_valid).toBe(false);

        // Restore membership
        await pool.query(`UPDATE memberships SET status = 'ACTIVE' WHERE id = '${membership}';`);

        // 4. When organisation is SUSPENDED: is_context_valid is FALSE
        await pool.query(`UPDATE organisations SET status = 'SUSPENDED' WHERE id = '${org}';`);
        const checkOrgSuspended = await pool.query<{ is_context_valid: boolean }>(
            `SELECT is_context_valid('${context}') as is_context_valid;`
        );
        expect(checkOrgSuspended.rows[0].is_context_valid).toBe(false);
    });

    it('enforces share_grants num_nonnulls(target_org_id, target_user_id) = 1', async () => {
        const user = (await pool.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-SHR', 'shr@archscale.test') RETURNING id;"
        )).rows[0].id;

        const org1 = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Org 1', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        const org2 = (await pool.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Org 2', 'subscriber', 'project_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        const grantor = (await pool.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${user}', '${org1}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        // Valid: target_org_id set, target_user_id NULL
        const grant1 = await pool.query(
            `INSERT INTO share_grants (source_organisation_id, target_org_id, target_user_id, resource_type, resource_id, granted_by, expires_at)
             VALUES ('${org1}', '${org2}', NULL, 'project', 'PRJ-101', '${grantor}', now() + interval '7 days') RETURNING id;`
        );
        expect(grant1.rows.length).toBe(1);

        // Invalid: BOTH target_org_id and target_user_id set
        await expect(
            pool.query(
                `INSERT INTO share_grants (source_organisation_id, target_org_id, target_user_id, resource_type, resource_id, granted_by, expires_at)
                 VALUES ('${org1}', '${org2}', '${user}', 'project', 'PRJ-102', '${grantor}', now() + interval '7 days');`
            )
        ).rejects.toThrow(/chk_share_grant_target_one/);

        // Invalid: NEITHER target_org_id nor target_user_id set
        await expect(
            pool.query(
                `INSERT INTO share_grants (source_organisation_id, target_org_id, target_user_id, resource_type, resource_id, granted_by, expires_at)
                 VALUES ('${org1}', NULL, NULL, 'project', 'PRJ-103', '${grantor}', now() + interval '7 days');`
            )
        ).rejects.toThrow(/chk_share_grant_target_one/);
    });
});
