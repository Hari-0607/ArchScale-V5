/**
 * Unit and Integration Tests for Allowed Authorization Paths (decide)
 * ARCHSCALE_TEST_DB_URL local tests
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase, RUNTIME_CONFIG } from '../setup/db_connection.js';
import pg from 'pg';
import { decide } from '../../src/authz/decide.js';
import { renewAccessContext } from '../../src/context/access_context.js';
import { VerifiedPrincipal } from '../../src/identity/types.js';

let adminPool: pg.Pool;
let runtimePool: pg.Pool;

const USER_OWNER_ID = '40000000-0000-0000-0000-000000000001';
const USER_LEADER_ID = '40000000-0000-0000-0000-000000000002';
const USER_INTERN_ID = '40000000-0000-0000-0000-000000000003';
const USER_FOUNDER_ID = '40000000-0000-0000-0000-000000000004';
const USER_STAFF_ID = '40000000-0000-0000-0000-000000000005';
const USER_MULTI_ID = '40000000-0000-0000-0000-000000000006';

const SUBSCRIBER_ORG_A_ID = '40000000-0000-0000-0000-000000000010';
const SUBSCRIBER_ORG_B_ID = '40000000-0000-0000-0000-000000000020';
const PLATFORM_ORG_ID = '00000000-0000-0000-0000-000000000001';

let wsAId: string;
let wsBId: string;
let wsPlatId: string;

let memOwnerId: string;
let memLeaderId: string;
let memInternId: string;
let memFounderId: string;
let memStaffPlatId: string;
let memMultiAId: string;
let memMultiBId: string;

let supportGrantId: string;

beforeAll(async () => {
    adminPool = await createIsolatedTestDatabase('archscale_test_authz_allowed');
    runtimePool = new pg.Pool({ ...RUNTIME_CONFIG, database: 'archscale_test_authz_allowed' });

    // Seed auth and mirror users
    const users = [
        [USER_OWNER_ID, 'owner@test.local', 'AS-OWNER'],
        [USER_LEADER_ID, 'leader@test.local', 'AS-LEADER'],
        [USER_INTERN_ID, 'intern@test.local', 'AS-INTERN'],
        [USER_FOUNDER_ID, 'founder@test.local', 'AS-FOUNDER'],
        [USER_STAFF_ID, 'staff@test.local', 'AS-STAFF'],
        [USER_MULTI_ID, 'multi@test.local', 'AS-MULTI']
    ];

    for (const [id, email, code] of users) {
        await adminPool.query(
            `INSERT INTO auth.users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING;`,
            [id, email]
        );
        await adminPool.query(
            `INSERT INTO public.users (id, user_code, email) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING;`,
            [id, code, email]
        );
    }

    // Seed Organisations (explicitly aal1 to test that leader at aal1 is allowed, while business_owner remains protected at aal2)
    await adminPool.query(`
        INSERT INTO public.organisations (id, name, portal, tenant_type_key, status, member_min_aal)
        VALUES 
            ($1, 'Subscriber Org A', 'subscriber', 'studio_owner', 'ACTIVE', 'aal1'),
            ($2, 'Subscriber Org B', 'subscriber', 'studio_owner', 'ACTIVE', 'aal1')
        ON CONFLICT (id) DO NOTHING;
    `, [SUBSCRIBER_ORG_A_ID, SUBSCRIBER_ORG_B_ID]);

    // Workspaces
    const wsARes = await adminPool.query(`
        INSERT INTO public.workspaces (organisation_id, name, is_active)
        VALUES ($1, 'Workspace A', true) RETURNING id;
    `, [SUBSCRIBER_ORG_A_ID]);
    wsAId = wsARes.rows[0].id;

    const wsBRes = await adminPool.query(`
        INSERT INTO public.workspaces (organisation_id, name, is_active)
        VALUES ($1, 'Workspace B', true) RETURNING id;
    `, [SUBSCRIBER_ORG_B_ID]);
    wsBId = wsBRes.rows[0].id;

    const wsPlatRes = await adminPool.query(`
        INSERT INTO public.workspaces (organisation_id, name, is_active)
        VALUES ($1, 'Platform Ops', true) RETURNING id;
    `, [PLATFORM_ORG_ID]);
    wsPlatId = wsPlatRes.rows[0].id;

    // Entitlements
    await adminPool.query(`INSERT INTO public.app_catalogue (app_key, name) VALUES ('core_billing', 'Core Billing') ON CONFLICT DO NOTHING;`);
    await adminPool.query(`INSERT INTO public.organisation_entitlements (organisation_id, app_key, is_enabled) VALUES ($1, 'core_billing', true) ON CONFLICT DO NOTHING;`, [SUBSCRIBER_ORG_A_ID]);
    await adminPool.query(`INSERT INTO public.organisation_entitlements (organisation_id, app_key, is_enabled) VALUES ($1, 'core_billing', true) ON CONFLICT DO NOTHING;`, [SUBSCRIBER_ORG_B_ID]);

    // Memberships
    const mOwner = await adminPool.query(`INSERT INTO public.memberships (organisation_id, user_id, role_key, status) VALUES ($1, $2, 'business_owner', 'ACTIVE') RETURNING id;`, [SUBSCRIBER_ORG_A_ID, USER_OWNER_ID]);
    memOwnerId = mOwner.rows[0].id;

    const mLeader = await adminPool.query(`INSERT INTO public.memberships (organisation_id, user_id, role_key, status) VALUES ($1, $2, 'leader', 'ACTIVE') RETURNING id;`, [SUBSCRIBER_ORG_A_ID, USER_LEADER_ID]);
    memLeaderId = mLeader.rows[0].id;

    const mIntern = await adminPool.query(`INSERT INTO public.memberships (organisation_id, user_id, role_key, status, expires_at) VALUES ($1, $2, 'intern', 'ACTIVE', now() + INTERVAL '90 days') RETURNING id;`, [SUBSCRIBER_ORG_A_ID, USER_INTERN_ID]);
    memInternId = mIntern.rows[0].id;

    const mFounder = await adminPool.query(`INSERT INTO public.memberships (organisation_id, user_id, role_key, status) VALUES ($1, $2, 'founder', 'ACTIVE') RETURNING id;`, [PLATFORM_ORG_ID, USER_FOUNDER_ID]);
    memFounderId = mFounder.rows[0].id;

    const mStaff = await adminPool.query(`INSERT INTO public.memberships (organisation_id, user_id, role_key, status) VALUES ($1, $2, 'client_servicing', 'ACTIVE') RETURNING id;`, [PLATFORM_ORG_ID, USER_STAFF_ID]);
    memStaffPlatId = mStaff.rows[0].id;

    // Multi-org user: business_owner in Org A, intern in Org B
    const mMultiA = await adminPool.query(`INSERT INTO public.memberships (organisation_id, user_id, role_key, status) VALUES ($1, $2, 'business_owner', 'ACTIVE') RETURNING id;`, [SUBSCRIBER_ORG_A_ID, USER_MULTI_ID]);
    memMultiAId = mMultiA.rows[0].id;

    const mMultiB = await adminPool.query(`INSERT INTO public.memberships (organisation_id, user_id, role_key, status, expires_at) VALUES ($1, $2, 'intern', 'ACTIVE', now() + INTERVAL '90 days') RETURNING id;`, [SUBSCRIBER_ORG_B_ID, USER_MULTI_ID]);
    memMultiBId = mMultiB.rows[0].id;

    // Support grant from platform staff into Org A
    const grantRes = await adminPool.query(`
        INSERT INTO public.support_access_grants (
            staff_membership_id, target_organisation_id, reason, expires_at
        ) VALUES ($1, $2, 'Allowed read path verification', now() + INTERVAL '4 hours')
        RETURNING id;
    `, [memStaffPlatId, SUBSCRIBER_ORG_A_ID]);
    supportGrantId = grantRes.rows[0].id;
});

afterAll(async () => {
    await runtimePool.end();
    await adminPool.end();
});

describe('02_allowed: Verification of Allowed Authorization Paths and Scopes', () => {
    it('1. business_owner on org.members.invite: DENIED at aal1, ALLOWED at aal2', async () => {
        const client = await adminPool.connect();
        try {
            // Case A: Context created with aal1
            const ctxAal1Res = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'sess_owner_1', $2::uuid, $3::uuid, 'aal1');`,
                [USER_OWNER_ID, SUBSCRIBER_ORG_A_ID, wsAId]
            );
            const ctxAal1Id = ctxAal1Res.rows[0].fn_create_access_context;

            const principalAal1: VerifiedPrincipal = {
                id: USER_OWNER_ID,
                email: 'owner@test.local',
                sessionId: 'sess_owner_1',
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };

            const decisionAal1 = await decide(client, principalAal1, ctxAal1Id, 'org.members.invite');
            expect(decisionAal1.allow).toBe(false);
            if (!decisionAal1.allow) {
                expect(decisionAal1.gateFailed).toBe(8);
                expect(decisionAal1.reasonCode).toBe('AUTH_AAL');
            }

            // Case B: Context created with aal2 (after MFA verify)
            const ctxAal2Res = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'sess_owner_2', $2::uuid, $3::uuid, 'aal2');`,
                [USER_OWNER_ID, SUBSCRIBER_ORG_A_ID, wsAId]
            );
            const ctxAal2Id = ctxAal2Res.rows[0].fn_create_access_context;

            const principalAal2: VerifiedPrincipal = {
                id: USER_OWNER_ID,
                email: 'owner@test.local',
                sessionId: 'sess_owner_2',
                aal: 'aal2',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };

            const decisionAal2 = await decide(client, principalAal2, ctxAal2Id, 'org.members.invite');
            expect(decisionAal2.allow).toBe(true);
            if (decisionAal2.allow) {
                expect(decisionAal2.roleKey).toBe('business_owner');
                expect(decisionAal2.organisationId).toBe(SUBSCRIBER_ORG_A_ID);
                expect(decisionAal2.aal).toBe('aal2');
            }
        } finally {
            client.release();
        }
    });

    it('2. leader on org.members.read: ALLOWED', async () => {
        const client = await adminPool.connect();
        try {
            const ctxRes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'sess_leader', $2::uuid, $3::uuid, 'aal1');`,
                [USER_LEADER_ID, SUBSCRIBER_ORG_A_ID, wsAId]
            );
            const contextId = ctxRes.rows[0].fn_create_access_context;

            const principal: VerifiedPrincipal = {
                id: USER_LEADER_ID,
                email: 'leader@test.local',
                sessionId: 'sess_leader',
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };

            const decision = await decide(client, principal, contextId, 'org.members.read');
            expect(decision.allow).toBe(true);
            if (decision.allow) {
                expect(decision.roleKey).toBe('leader');
            }
        } finally {
            client.release();
        }
    });

    it('3. intern on org.members.read: DENIED because seeds grant read only to owner and leader', async () => {
        const client = await adminPool.connect();
        try {
            const ctxRes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'sess_intern', $2::uuid, $3::uuid, 'aal1');`,
                [USER_INTERN_ID, SUBSCRIBER_ORG_A_ID, wsAId]
            );
            const contextId = ctxRes.rows[0].fn_create_access_context;

            const principal: VerifiedPrincipal = {
                id: USER_INTERN_ID,
                email: 'intern@test.local',
                sessionId: 'sess_intern',
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };

            const decision = await decide(client, principal, contextId, 'org.members.read');
            expect(decision.allow).toBe(false);
            if (!decision.allow) {
                expect(decision.gateFailed).toBe(8);
                expect(decision.reasonCode).toBe('AUTH_PERMISSION');
            }
        } finally {
            client.release();
        }
    });

    it('4. founder at aal2 on platform.organisations.read: ALLOWED', async () => {
        const client = await adminPool.connect();
        try {
            const ctxRes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'sess_fndr', $2::uuid, $3::uuid, 'aal2');`,
                [USER_FOUNDER_ID, PLATFORM_ORG_ID, wsPlatId]
            );
            const contextId = ctxRes.rows[0].fn_create_access_context;

            const principal: VerifiedPrincipal = {
                id: USER_FOUNDER_ID,
                email: 'founder@test.local',
                sessionId: 'sess_fndr',
                aal: 'aal2',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };

            const decision = await decide(client, principal, contextId, 'platform.organisations.read');
            expect(decision.allow).toBe(true);
            if (decision.allow) {
                expect(decision.portal).toBe('platform');
                expect(decision.roleKey).toBe('founder');
            }
        } finally {
            client.release();
        }
    });

    it('5. renewal succeeds within 24h cap', async () => {
        const client = await adminPool.connect();
        try {
            const ctxRes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'sess_renew', $2::uuid, $3::uuid, 'aal1');`,
                [USER_OWNER_ID, SUBSCRIBER_ORG_A_ID, wsAId]
            );
            const contextId = ctxRes.rows[0].fn_create_access_context;

            const renewRes = await client.query<{ context_id: string; expires_at: Date }>(
                `SELECT * FROM fn_renew_access_context($1::uuid, $2::uuid, 'sess_renew');`,
                [contextId, USER_OWNER_ID]
            );
            expect(renewRes.rows[0].context_id).toBe(contextId);
            expect(new Date(renewRes.rows[0].expires_at).getTime()).toBeGreaterThan(Date.now());
        } finally {
            client.release();
        }
    });

    it('6. platform staff in support context can read (ALLOWED) but not write (DENIED)', async () => {
        const client = await adminPool.connect();
        try {
            const ctxRes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, $2::text, $3::uuid, $4::uuid, 'aal2', $5::uuid);`,
                [USER_STAFF_ID, 'sess_supp', SUBSCRIBER_ORG_A_ID, wsAId, supportGrantId]
            );
            const supportCtxId = ctxRes.rows[0].fn_create_access_context;

            const principal: VerifiedPrincipal = {
                id: USER_STAFF_ID,
                email: 'staff@test.local',
                sessionId: 'sess_supp',
                aal: 'aal2',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };

            // Read path on org.members.read (grant gives client_servicing access)
            // Add permission for client servicing to read members in support context
            await adminPool.query(
                `INSERT INTO public.role_permissions (role_key, permission_key) VALUES ('client_servicing', 'org.members.read') ON CONFLICT DO NOTHING;`
            );

            const readDecision = await decide(client, principal, supportCtxId, 'org.members.read');
            if (!readDecision.allow) {
                console.log('Test 6 denial details:', readDecision);
            }
            expect(readDecision.allow).toBe(true);

            // Write path on org.members.invite is DENIED by Gate 5
            const writeDecision = await decide(client, principal, supportCtxId, 'org.members.invite');
            expect(writeDecision.allow).toBe(false);
            if (!writeDecision.allow) {
                expect(writeDecision.gateFailed).toBe(5);
                expect(writeDecision.reasonCode).toBe('AUTH_SUPPORT_READ_ONLY');
            }
        } finally {
            client.release();
        }
    });

    it('7. two-membership user: owner rights in Org A, never leaks to Org B', async () => {
        const client = await adminPool.connect();
        try {
            // Context in Org A (as business_owner at aal2)
            const ctxARes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'sess_multi', $2::uuid, $3::uuid, 'aal2');`,
                [USER_MULTI_ID, SUBSCRIBER_ORG_A_ID, wsAId]
            );
            const contextAId = ctxARes.rows[0].fn_create_access_context;

            // Context in Org B (as intern at aal2)
            const ctxBRes = await client.query<{ fn_create_access_context: string }>(
                `SELECT fn_create_access_context($1::uuid, 'sess_multi', $2::uuid, $3::uuid, 'aal2');`,
                [USER_MULTI_ID, SUBSCRIBER_ORG_B_ID, wsBId]
            );
            const contextBId = ctxBRes.rows[0].fn_create_access_context;

            const principal: VerifiedPrincipal = {
                id: USER_MULTI_ID,
                email: 'multi@test.local',
                sessionId: 'sess_multi',
                aal: 'aal2',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };

            // Org A decision: owner invite ALLOWED
            const decisionA = await decide(client, principal, contextAId, 'org.members.invite');
            expect(decisionA.allow).toBe(true);
            if (decisionA.allow) {
                expect(decisionA.organisationId).toBe(SUBSCRIBER_ORG_A_ID);
                expect(decisionA.roleKey).toBe('business_owner');
            }

            // Org B decision: intern invite DENIED
            const decisionB = await decide(client, principal, contextBId, 'org.members.invite');
            expect(decisionB.allow).toBe(false);
            if (!decisionB.allow) {
                expect(decisionB.gateFailed).toBe(8);
                expect(decisionB.reasonCode).toBe('AUTH_PERMISSION');
            }
        } finally {
            client.release();
        }
    });

    it('8. all permissions in ROUTE_PERMISSIONS exist in database and are mapped to at least one role', async () => {
        const client = await adminPool.connect();
        try {
            const { ROUTE_PERMISSIONS } = await import('../../src/config/route_permissions.js');
            const routePermKeys = Array.from(new Set(Object.values(ROUTE_PERMISSIONS).map(rp => rp.permission)));

            const res = await client.query<{ key: string; role_count: string }>(`
                SELECT p.key, COUNT(rp.role_key) AS role_count
                FROM public.permissions p
                LEFT JOIN public.role_permissions rp ON rp.permission_key = p.key
                WHERE p.key = ANY($1::text[])
                GROUP BY p.key;
            `, [routePermKeys]);

            const foundKeys = new Map<string, number>();
            for (const row of res.rows) {
                foundKeys.set(row.key, parseInt(row.role_count, 10));
            }

            for (const requiredPerm of routePermKeys) {
                expect(foundKeys.has(requiredPerm)).toBe(true);
                const roleCount = foundKeys.get(requiredPerm) || 0;
                expect(roleCount).toBeGreaterThan(0);
            }
        } finally {
            client.release();
        }
    });
});
