/**
 * Unit and Integration Tests for Authorization Denials (Gates 0 - 8)
 * Tests gate evaluation using decide() with real context and seed fixtures.
 * ARCHSCALE_TEST_DB_URL local tests
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase, RUNTIME_CONFIG } from '../setup/db_connection.js';
import pg from 'pg';
import { decide } from '../../src/authz/decide.js';
import { createAccessContext } from '../../src/context/access_context.js';
import { VerifiedPrincipal } from '../../src/identity/types.js';

let adminPool: pg.Pool;
let runtimePool: pg.Pool;

const USER_ALICE_ID = '30000000-0000-0000-0000-000000000001';
const USER_BOB_ID = '30000000-0000-0000-0000-000000000002';
const USER_STAFF_ID = '30000000-0000-0000-0000-000000000003';

const SUBSCRIBER_ORG_ID = '30000000-0000-0000-0000-000000000010';
const PLATFORM_ORG_ID = '00000000-0000-0000-0000-000000000001';

let workspaceId: string;
let membershipAliceId: string;
let membershipStaffId: string;
let validContextId: string;
let supportGrantId: string;

const SESSION_ALICE = 'session_alice_123';
const SESSION_STAFF = 'session_staff_123';

beforeAll(async () => {
    adminPool = await createIsolatedTestDatabase('archscale_test_authz_denials');
    runtimePool = new pg.Pool({ ...RUNTIME_CONFIG, database: 'archscale_test_authz_denials' });

    // Seed auth and mirror users
    await adminPool.query(`
        INSERT INTO auth.users (id, email) VALUES
            ($1, 'alice@test.local'),
            ($2, 'bob@test.local'),
            ($3, 'staff@test.local')
        ON CONFLICT (id) DO NOTHING;
    `, [USER_ALICE_ID, USER_BOB_ID, USER_STAFF_ID]);

    await adminPool.query(`
        INSERT INTO public.users (id, user_code, email) VALUES
            ($1, 'AS-TESTALICE', 'alice@test.local'),
            ($2, 'AS-TESTBOB', 'bob@test.local'),
            ($3, 'AS-TESTSTAFF', 'staff@test.local')
        ON CONFLICT (id) DO NOTHING;
    `, [USER_ALICE_ID, USER_BOB_ID, USER_STAFF_ID]);

    // Seed organisations
    await adminPool.query(`
        INSERT INTO public.organisations (id, name, portal, tenant_type_key, status)
        VALUES 
            ($1, 'Active Studio Org', 'subscriber', 'studio_owner', 'ACTIVE')
        ON CONFLICT (id) DO NOTHING;
    `, [SUBSCRIBER_ORG_ID]);

    // Active workspace
    const wsRes = await adminPool.query(`
        INSERT INTO public.workspaces (organisation_id, name, is_active)
        VALUES ($1, 'Main Workspace', true)
        RETURNING id;
    `, [SUBSCRIBER_ORG_ID]);
    workspaceId = wsRes.rows[0].id;

    // Entitlement for subscriber
    await adminPool.query(`INSERT INTO public.app_catalogue (app_key, name) VALUES ('core_billing', 'Core Billing') ON CONFLICT DO NOTHING;`);
    await adminPool.query(`INSERT INTO public.organisation_entitlements (organisation_id, app_key, is_enabled) VALUES ($1, 'core_billing', true) ON CONFLICT DO NOTHING;`, [SUBSCRIBER_ORG_ID]);

    // Alice active membership (business_owner)
    const memRes = await adminPool.query(`
        INSERT INTO public.memberships (organisation_id, user_id, role_key, status)
        VALUES ($1, $2, 'business_owner', 'ACTIVE')
        RETURNING id;
    `, [SUBSCRIBER_ORG_ID, USER_ALICE_ID]);
    membershipAliceId = memRes.rows[0].id;

    // Staff active membership in platform org (founder)
    const staffMemRes = await adminPool.query(`
        INSERT INTO public.memberships (organisation_id, user_id, role_key, status)
        VALUES ($1, $2, 'founder', 'ACTIVE')
        RETURNING id;
    `, [PLATFORM_ORG_ID, USER_STAFF_ID]);
    membershipStaffId = staffMemRes.rows[0].id;

    // Role permissions
    await adminPool.query(`
        INSERT INTO public.role_permissions (role_key, permission_key)
        VALUES 
            ('business_owner', 'org.members.read'),
            ('founder', 'platform.orgs.read')
        ON CONFLICT DO NOTHING;
    `);

    // Create valid context using fn_create_access_context
    const client = await adminPool.connect();
    try {
        const ctxRes = await client.query<{ fn_create_access_context: string }>(
            `SELECT fn_create_access_context($1::uuid, $2::text, $3::uuid, $4::uuid, 'aal1');`,
            [USER_ALICE_ID, SESSION_ALICE, SUBSCRIBER_ORG_ID, workspaceId]
        );
        validContextId = ctxRes.rows[0].fn_create_access_context;
    } finally {
        client.release();
    }
});

afterAll(async () => {
    await runtimePool.end();
    await adminPool.end();
});

describe('Authorization Denial Gates (decide)', () => {
    it('Gate 0: Fails on non-existent or forged context ID', async () => {
        const client = await adminPool.connect();
        try {
            const principal: VerifiedPrincipal = {
                id: USER_ALICE_ID,
                email: 'alice@test.local',
                sessionId: SESSION_ALICE,
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };
            const decision = await decide(client, principal, '00000000-0000-0000-0000-000000000000', 'org.members.read');
            expect(decision.allow).toBe(false);
            if (!decision.allow) {
                expect(decision.gateFailed).toBe(0);
                expect(decision.reasonCode).toBe('AUTH_CONTEXT_INVALID');
            }
        } finally {
            client.release();
        }
    });

    it('Gate 0: Fails on session ID mismatch', async () => {
        const client = await adminPool.connect();
        try {
            const principal: VerifiedPrincipal = {
                id: USER_ALICE_ID,
                email: 'alice@test.local',
                sessionId: 'session_forged_different_123',
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };
            const decision = await decide(client, principal, validContextId, 'org.members.read');
            expect(decision.allow).toBe(false);
            if (!decision.allow) {
                expect(decision.gateFailed).toBe(0);
                expect(decision.reasonCode).toBe('AUTH_CONTEXT_MISMATCH');
            }
        } finally {
            client.release();
        }
    });

    it('Gate 0: Fails on expired context', async () => {
        const client = await adminPool.connect();
        try {
            // Create context and manually expire it
            const ctxRes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'session_exp', $2::uuid, $3::uuid, 'aal1');`,
                [USER_ALICE_ID, SUBSCRIBER_ORG_ID, workspaceId]
            );
            const expCtxId = ctxRes.rows[0].fn_create_access_context;
            await client.query(`UPDATE public.access_contexts SET expires_at = now() - INTERVAL '1 minute' WHERE id = $1;`, [expCtxId]);

            const principal: VerifiedPrincipal = {
                id: USER_ALICE_ID,
                email: 'alice@test.local',
                sessionId: 'session_exp',
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };
            const decision = await decide(client, principal, expCtxId, 'org.members.read');
            expect(decision.allow).toBe(false);
            if (!decision.allow) {
                expect(decision.gateFailed).toBe(0);
                expect(decision.reasonCode).toBe('AUTH_CONTEXT_INVALID');
            }
        } finally {
            client.release();
        }
    });

    it('Gate 0: Fails on revoked context', async () => {
        const client = await adminPool.connect();
        try {
            const ctxRes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'session_rev', $2::uuid, $3::uuid, 'aal1');`,
                [USER_ALICE_ID, SUBSCRIBER_ORG_ID, workspaceId]
            );
            const revCtxId = ctxRes.rows[0].fn_create_access_context;
            await client.query(`UPDATE public.access_contexts SET revoked_at = now() WHERE id = $1;`, [revCtxId]);

            const principal: VerifiedPrincipal = {
                id: USER_ALICE_ID,
                email: 'alice@test.local',
                sessionId: 'session_rev',
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };
            const decision = await decide(client, principal, revCtxId, 'org.members.read');
            expect(decision.allow).toBe(false);
            if (!decision.allow) {
                expect(decision.gateFailed).toBe(0);
                expect(decision.reasonCode).toBe('AUTH_CONTEXT_INVALID');
            }
        } finally {
            client.release();
        }
    });

    it('Gate 1: Fails on inactive organisation', async () => {
        const client = await adminPool.connect();
        try {
            // Create a dedicated organisation that we suspend
            const orgSuspRes = await client.query(`
                INSERT INTO public.organisations (name, portal, tenant_type_key, status)
                VALUES ('Temp Studio Org', 'subscriber', 'studio_owner', 'ACTIVE')
                RETURNING id;
            `);
            const orgSuspId = orgSuspRes.rows[0].id;

            const wsRes = await client.query(`
                INSERT INTO public.workspaces (organisation_id, name, is_active)
                VALUES ($1, 'Temp WS', true) RETURNING id;
            `, [orgSuspId]);
            const wsSuspId = wsRes.rows[0].id;

            await client.query(`
                INSERT INTO public.organisation_entitlements (organisation_id, app_key, is_enabled)
                VALUES ($1, 'core_billing', true);
            `, [orgSuspId]);

            const memRes = await client.query(`
                INSERT INTO public.memberships (organisation_id, user_id, role_key, status)
                VALUES ($1, $2, 'business_owner', 'ACTIVE') RETURNING id;
            `, [orgSuspId, USER_ALICE_ID]);

            const ctxRes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'sess_temp_org', $2::uuid, $3::uuid, 'aal1');`,
                [USER_ALICE_ID, orgSuspId, wsSuspId]
            );
            const tempCtxId = ctxRes.rows[0].fn_create_access_context;

            // Now suspend the organisation
            await client.query(`UPDATE public.organisations SET status = 'SUSPENDED' WHERE id = $1;`, [orgSuspId]);

            const principal: VerifiedPrincipal = {
                id: USER_ALICE_ID,
                email: 'alice@test.local',
                sessionId: 'sess_temp_org',
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };
            const decision = await decide(client, principal, tempCtxId, 'org.members.read');
            expect(decision.allow).toBe(false);
            if (!decision.allow) {
                expect(decision.gateFailed).toBe(1);
                expect(decision.reasonCode).toBe('AUTH_ORG_INACTIVE');
            }
        } finally {
            client.release();
        }
    });

    it('Gate 2: Fails on expired membership', async () => {
        const client = await adminPool.connect();
        try {
            // Expire Alice's membership
            await client.query(`UPDATE public.memberships SET expires_at = now() - INTERVAL '1 minute' WHERE id = $1;`, [membershipAliceId]);

            const principal: VerifiedPrincipal = {
                id: USER_ALICE_ID,
                email: 'alice@test.local',
                sessionId: SESSION_ALICE,
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };
            const decision = await decide(client, principal, validContextId, 'org.members.read');
            expect(decision.allow).toBe(false);
            if (!decision.allow) {
                expect(decision.gateFailed).toBe(2);
                expect(decision.reasonCode).toBe('AUTH_MEMBERSHIP');
            }

            // Restore membership
            await client.query(`UPDATE public.memberships SET expires_at = NULL WHERE id = $1;`, [membershipAliceId]);
        } finally {
            client.release();
        }
    });

    it('Gate 4: Fails when subscriber calls platform route', async () => {
        const client = await adminPool.connect();
        try {
            const principal: VerifiedPrincipal = {
                id: USER_ALICE_ID,
                email: 'alice@test.local',
                sessionId: SESSION_ALICE,
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };
            const decision = await decide(client, principal, validContextId, 'platform.organisations.read');
            expect(decision.allow).toBe(false);
            if (!decision.allow) {
                expect(decision.gateFailed).toBe(4);
                expect(decision.reasonCode).toBe('AUTH_PORTAL');
            }
        } finally {
            client.release();
        }
    });

    it('Gate 5: Rejects mutation on support context', async () => {
        const client = await adminPool.connect();
        try {
            // Create active support grant
            const grantRes = await client.query(`
                INSERT INTO public.support_access_grants (
                    staff_membership_id,
                    target_organisation_id,
                    reason,
                    expires_at
                ) VALUES ($1, $2, 'Investigating billing issue', now() + INTERVAL '2 hours')
                RETURNING id;
            `, [membershipStaffId, SUBSCRIBER_ORG_ID]);
            supportGrantId = grantRes.rows[0].id;

            // Create support context via fn_create_access_context
            const ctxRes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, $2::text, $3::uuid, $4::uuid, 'aal2', $5::uuid);`,
                [USER_STAFF_ID, SESSION_STAFF, SUBSCRIBER_ORG_ID, workspaceId, supportGrantId]
            );
            const supportCtxId = ctxRes.rows[0].fn_create_access_context;

            const principal: VerifiedPrincipal = {
                id: USER_STAFF_ID,
                email: 'staff@test.local',
                sessionId: SESSION_STAFF,
                aal: 'aal2',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };

            // Call mutation route org.members.invite
            const decision = await decide(client, principal, supportCtxId, 'org.members.invite');
            expect(decision.allow).toBe(false);
            if (!decision.allow) {
                expect(decision.gateFailed).toBe(5);
                expect(decision.reasonCode).toBe('AUTH_SUPPORT_READ_ONLY');
            }
        } finally {
            client.release();
        }
    });

    it('Gate 8: Denies intern role on invite route', async () => {
        const client = await adminPool.connect();
        try {
            // Bob as intern
            await client.query(`
                INSERT INTO public.memberships (organisation_id, user_id, role_key, status, expires_at)
                VALUES ($1, $2, 'intern', 'ACTIVE', now() + INTERVAL '30 days')
                ON CONFLICT (user_id, organisation_id) DO NOTHING;
            `, [SUBSCRIBER_ORG_ID, USER_BOB_ID]);

            const ctxRes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'session_bob', $2::uuid, $3::uuid, 'aal1');`,
                [USER_BOB_ID, SUBSCRIBER_ORG_ID, workspaceId]
            );
            const bobCtxId = ctxRes.rows[0].fn_create_access_context;

            const principal: VerifiedPrincipal = {
                id: USER_BOB_ID,
                email: 'bob@test.local',
                sessionId: 'session_bob',
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };
            const decision = await decide(client, principal, bobCtxId, 'org.members.invite');
            expect(decision.allow).toBe(false);
            if (!decision.allow) {
                expect(decision.gateFailed).toBe(8);
                expect(decision.reasonCode).toBe('AUTH_PERMISSION');
            }
        } finally {
            client.release();
        }
    });

    it('Gate 8: Denies platform route when AAL is aal1', async () => {
        const client = await adminPool.connect();
        try {
            const platWsRes = await client.query(`
                INSERT INTO public.workspaces (organisation_id, name, is_active)
                VALUES ($1, 'Platform Admin WS', true) RETURNING id;
            `, [PLATFORM_ORG_ID]);
            const platWsId = platWsRes.rows[0].id;

            const ctxRes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'sess_staff_aal1', $2::uuid, $3::uuid, 'aal1');`,
                [USER_STAFF_ID, PLATFORM_ORG_ID, platWsId]
            );
            const platCtxId = ctxRes.rows[0].fn_create_access_context;

            const principal: VerifiedPrincipal = {
                id: USER_STAFF_ID,
                email: 'staff@test.local',
                sessionId: 'sess_staff_aal1',
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };
            const decision = await decide(client, principal, platCtxId, 'platform.organisations.read');
            expect(decision.allow).toBe(false);
            if (!decision.allow) {
                expect(decision.gateFailed).toBe(8);
                expect(decision.reasonCode).toBe('AUTH_AAL');
            }
        } finally {
            client.release();
        }
    });
});
