import { describe, it, expect, beforeEach } from 'vitest';
import { createTestDatabase } from '../setup/db_connection.js';
import { PGlite } from '@electric-sql/pglite';

describe('Migrations 001 - 004 Schema & Invariants Conformance', () => {
    let db: PGlite;

    beforeEach(async () => {
        db = await createTestDatabase();
    });

    it('enforces exactly ONE platform organisation via partial unique index', async () => {
        // Platform org was seeded in migration 003
        const result = await db.query<{ count: string }>(
            "SELECT count(*)::text FROM organisations WHERE portal = 'platform';"
        );
        expect(parseInt(result.rows[0].count)).toBe(1);

        // Attempting to insert a second platform org must be rejected
        await expect(
            db.query(
                "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Rogue Platform Org', 'platform', NULL, 'ACTIVE');"
            )
        ).rejects.toThrow();
    });

    it('enforces organisations.tenant_type_key is NULL iff portal = platform', async () => {
        // Platform org cannot have a tenant_type_key
        await expect(
            db.query(
                "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Invalid Platform', 'platform', 'studio_owner', 'ACTIVE');"
            )
        ).rejects.toThrow();

        // Subscriber org MUST have a tenant_type_key
        await expect(
            db.query(
                "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Invalid Subscriber', 'subscriber', NULL, 'ACTIVE');"
            )
        ).rejects.toThrow();

        // Valid subscriber org succeeds
        const insertSub = await db.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Studio A', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        );
        expect(insertSub.rows.length).toBe(1);
    });

    it('enforces users table as an identity mirror with NO roles/tenants and unique user_code', async () => {
        const user1 = await db.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-001', 'user1@archscale.test') RETURNING id;"
        );
        expect(user1.rows.length).toBe(1);

        // Duplicate user_code must fail
        await expect(
            db.query("INSERT INTO users (user_code, email) VALUES ('USR-001', 'user2@archscale.test');")
        ).rejects.toThrow();

        // Duplicate email must fail
        await expect(
            db.query("INSERT INTO users (user_code, email) VALUES ('USR-002', 'user1@archscale.test');")
        ).rejects.toThrow();
    });

    it('enforces seat accounting invariant: allocated_seats <= seat_limit', async () => {
        // Create an app in app_catalogue
        await db.query(
            "INSERT INTO app_catalogue (app_key, name, description) VALUES ('app_canvas', 'Arch Canvas', 'CAD & BIM workspace');"
        );

        // Create an organisation
        const orgRes = await db.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('BIM Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        );
        const orgId = orgRes.rows[0].id;

        // Inserting seats with limit 5, allocated 2 succeeds
        await db.query(
            `INSERT INTO organisation_seats (organisation_id, app_key, role_key, seat_limit, allocated_seats)
             VALUES ('${orgId}', 'app_canvas', 'business_owner', 5, 2);`
        );

        // Updating allocated_seats to 6 (exceeding limit 5) must fail check constraint
        await expect(
            db.query(
                `UPDATE organisation_seats SET allocated_seats = 6 WHERE organisation_id = '${orgId}' AND app_key = 'app_canvas';`
            )
        ).rejects.toThrow();
    });

    it('enforces access_contexts 24-hour lifetime hard check', async () => {
        // Setup user, org, workspace, membership
        const user = (await db.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-CTX', 'ctx@archscale.test') RETURNING id;"
        )).rows[0].id;

        const org = (await db.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Context Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        const workspace = (await db.query<{ id: string }>(
            `INSERT INTO workspaces (organisation_id, name) VALUES ('${org}', 'Main Workspace') RETURNING id;`
        )).rows[0].id;

        const membership = (await db.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${user}', '${org}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        // Valid context with 12 hour expiry succeeds
        const validContext = await db.query<{ id: string }>(
            `INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at)
             VALUES ('${user}', 'sess_valid', '${org}', '${workspace}', '${membership}', now() + interval '12 hours')
             RETURNING id;`
        );
        expect(validContext.rows.length).toBe(1);

        // Invalid context with 25 hour expiry fails check constraint
        await expect(
            db.query(
                `INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at)
                 VALUES ('${user}', 'sess_invalid', '${org}', '${workspace}', '${membership}', now() + interval '25 hours');`
            )
        ).rejects.toThrow();
    });

    it('evaluates is_context_valid correctly across org and membership states', async () => {
        // Setup user, org, workspace, membership
        const user = (await db.query<{ id: string }>(
            "INSERT INTO users (user_code, email) VALUES ('USR-VAL', 'val@archscale.test') RETURNING id;"
        )).rows[0].id;

        const org = (await db.query<{ id: string }>(
            "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Validation Studio', 'subscriber', 'studio_owner', 'ACTIVE') RETURNING id;"
        )).rows[0].id;

        const workspace = (await db.query<{ id: string }>(
            `INSERT INTO workspaces (organisation_id, name) VALUES ('${org}', 'Default Workspace') RETURNING id;`
        )).rows[0].id;

        const membership = (await db.query<{ id: string }>(
            `INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES ('${user}', '${org}', 'business_owner', 'ACTIVE') RETURNING id;`
        )).rows[0].id;

        const context = (await db.query<{ id: string }>(
            `INSERT INTO access_contexts (user_id, session_id, organisation_id, workspace_id, membership_id, expires_at)
             VALUES ('${user}', 'sess_test', '${org}', '${workspace}', '${membership}', now() + interval '2 hours')
             RETURNING id;`
        )).rows[0].id;

        // 1. When everything is ACTIVE and unexpired: is_context_valid is TRUE
        const check1 = await db.query<{ is_context_valid: boolean }>(
            `SELECT is_context_valid('${context}') as is_context_valid;`
        );
        expect(check1.rows[0].is_context_valid).toBe(true);

        // 2. When context is revoked: is_context_valid is FALSE
        await db.query(`UPDATE access_contexts SET revoked_at = now() WHERE id = '${context}';`);
        const checkRevoked = await db.query<{ is_context_valid: boolean }>(
            `SELECT is_context_valid('${context}') as is_context_valid;`
        );
        expect(checkRevoked.rows[0].is_context_valid).toBe(false);

        // Unrevoke for next test
        await db.query(`UPDATE access_contexts SET revoked_at = NULL WHERE id = '${context}';`);

        // 3. When membership is SUSPENDED: is_context_valid is FALSE
        await db.query(`UPDATE memberships SET status = 'SUSPENDED' WHERE id = '${membership}';`);
        const checkMemSuspended = await db.query<{ is_context_valid: boolean }>(
            `SELECT is_context_valid('${context}') as is_context_valid;`
        );
        expect(checkMemSuspended.rows[0].is_context_valid).toBe(false);

        // Restore membership
        await db.query(`UPDATE memberships SET status = 'ACTIVE' WHERE id = '${membership}';`);

        // 4. When organisation is SUSPENDED: is_context_valid is FALSE
        await db.query(`UPDATE organisations SET status = 'SUSPENDED' WHERE id = '${org}';`);
        const checkOrgSuspended = await db.query<{ is_context_valid: boolean }>(
            `SELECT is_context_valid('${context}') as is_context_valid;`
        );
        expect(checkOrgSuspended.rows[0].is_context_valid).toBe(false);
    });

    it('verifies seed data contains expected platform roles and subscriber roles', async () => {
        const platformRoles = await db.query<{ key: string; level: number }>(
            "SELECT key, level FROM roles WHERE portal = 'platform' ORDER BY level DESC;"
        );
        expect(platformRoles.rows.map(r => r.key)).toEqual([
            'founder',
            'developer',
            'client_servicing',
            'accounts'
        ]);

        const subscriberRoles = await db.query<{ key: string; level: number }>(
            "SELECT key, level FROM roles WHERE portal = 'subscriber' ORDER BY level DESC;"
        );
        expect(subscriberRoles.rows.map(r => r.key)).toEqual([
            'business_owner',
            'leader',
            'manager_coordinator',
            'executive',
            'intern',
            'collaborator',
            'guest'
        ]);
    });
});
