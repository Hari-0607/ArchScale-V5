/**
 * Migration 014 Test Suite: Tests First
 *
 * Verifies all database-level guarantees of Migration 014:
 *   1. memberships: department, job_role, reporting_manager_membership_id
 *      - Manager must be in the same organisation
 *      - Manager cannot be self
 *      - Cycle detection trigger rejects circular chains (A -> B -> A, A -> B -> C -> A)
 *      - Manager must be ACTIVE
 *   2. invitations:
 *      - status enum: Pending, Sent, Accepted, Expired, Revoked (single spelling)
 *      - unique Pending per (organisation_id, lower(email))
 *      - columns: token_hash, target_role_key, access_profile_id, expires_at,
 *        invited_by_membership_id, department, job_role, reporting_manager_membership_id,
 *        sent_at, accepted_at, revoked_at, resend_count
 *   3. organisations.member_min_aal:
 *      - 'aal1' or 'aal2', DEFAULT 'aal2'
 *      - Effective minimum = max(roles.min_aal, organisations.member_min_aal)
 *      - aal2 roles can never be lowered by org setting (org at aal1 never lowers business_owner)
 *      - member in org set to aal2 is denied at aal1
 *      - only business_owner at aal2 can change it via fn_set_organisation_mfa_requirement (parameterless context)
 *   4. access_profiles:
 *      - Can attach to ANY subscriber role via role_key
 *      - memberships.profile_id validated: mismatched role_key or org rejected
 *      - Effective permissions = role permissions + profile permissions
 *      - fn_get_effective_permissions() derives from active context; another org's membership returns empty {}
 *   5. RLS on memberships and invitations:
 *      - Member sees only their own membership row
 *      - Member sees only invitations sent to their own email
 *   6. Definer listing functions:
 *      - fn_list_org_members() (requires org.members.read)
 *      - fn_list_org_invitations() (requires org.members.invite)
 *      - guest, collaborator, intern, executive cannot list
 *      - leader and business_owner can list
 *      - support context can read but cannot write
 *   7. auth_rate_limits:
 *      - direct DML revoked from archscale_app_runtime
 *      - fn_rate_limit_hit(key, action, max_attempts, window_seconds) Security Definer
 *      - action allowlist enforced
 *      - concurrent calls atomic; never exceed max_attempts
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase, RUNTIME_CONFIG } from '../setup/db_connection.js';
import { decide } from '../../src/authz/decide.js';
import { VerifiedPrincipal } from '../../src/identity/types.js';
import pg from 'pg';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let adminPool: pg.Pool;
let runtimePool: pg.Pool;

const USER_OWNER_ID   = '30000000-0000-0000-0000-000000000001';
const USER_MGR_ID     = '30000000-0000-0000-0000-000000000002';
const USER_EXEC_ID    = '30000000-0000-0000-0000-000000000003';
const USER_INTERN_ID  = '30000000-0000-0000-0000-000000000004';
const USER_STAFF_ID   = '30000000-0000-0000-0000-000000000005';
const USER_LEADER_ID  = '30000000-0000-0000-0000-000000000006';
const USER_GUEST_ID   = '30000000-0000-0000-0000-000000000007';
const USER_COLLAB_ID  = '30000000-0000-0000-0000-000000000008';

const ORG_A_ID = '30000000-0000-0000-0000-000000000010';
const ORG_B_ID = '30000000-0000-0000-0000-000000000020';
const PLATFORM_ORG_ID = '00000000-0000-0000-0000-000000000001';

let ownerMembershipId: string;
let mgrMembershipId: string;
let execMembershipId: string;
let internMembershipId: string;
let staffMembershipId: string;
let leaderMembershipId: string;
let guestMembershipId: string;
let collabMembershipId: string;
let workspaceAId: string;
let supportGrantId: string;

beforeAll(async () => {
    adminPool = await createIsolatedTestDatabase('archscale_test_014');

    // Seed auth.users & mirror
    const testUsers = [
        [USER_OWNER_ID, 'owner@studio.test', 'AS-OWNER01'],
        [USER_MGR_ID, 'mgr@studio.test', 'AS-MGR01'],
        [USER_EXEC_ID, 'exec@studio.test', 'AS-EXEC01'],
        [USER_INTERN_ID, 'intern@studio.test', 'AS-INT01'],
        [USER_STAFF_ID, 'staff@platform.test', 'AS-STAFF01'],
        [USER_LEADER_ID, 'leader@studio.test', 'AS-LEAD01'],
        [USER_GUEST_ID, 'guest@studio.test', 'AS-GST01'],
        [USER_COLLAB_ID, 'collab@studio.test', 'AS-COL01'],
    ];
    for (const [uid, email, code] of testUsers) {
        await adminPool.query('INSERT INTO auth.users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING;', [uid, email]);
        await adminPool.query('INSERT INTO public.users (id, email, user_code) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING;', [uid, email, code]);
    }

    // Seed organisations
    await adminPool.query(`
        INSERT INTO public.organisations (id, name, portal, tenant_type_key, status, member_min_aal)
        VALUES 
            ($1, 'Studio Design Org', 'subscriber', 'studio_owner', 'ACTIVE', 'aal2'),
            ($2, 'Other Tenant Org', 'subscriber', 'studio_owner', 'ACTIVE', 'aal2')
        ON CONFLICT (id) DO NOTHING;
    `, [ORG_A_ID, ORG_B_ID]);

    // App & Entitlement for ORG_A
    await adminPool.query(`
        INSERT INTO public.app_catalogue (app_key, name, description)
        VALUES ('core_portal', 'Core Portal', 'Main portal')
        ON CONFLICT (app_key) DO NOTHING;
    `);

    await adminPool.query(`
        INSERT INTO public.organisation_entitlements (organisation_id, app_key, is_enabled)
        VALUES ($1, 'core_portal', true)
        ON CONFLICT DO NOTHING;
    `, [ORG_A_ID]);

    // Workspace
    const wsRes = await adminPool.query(`
        INSERT INTO public.workspaces (organisation_id, name, is_active)
        VALUES ($1, 'Main Workspace', true)
        RETURNING id;
    `, [ORG_A_ID]);
    workspaceAId = wsRes.rows[0].id;

    // Memberships
    const mOwner = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, is_primary_owner)
        VALUES ($1, $2, 'business_owner', 'ACTIVE', true) RETURNING id;
    `, [USER_OWNER_ID, ORG_A_ID]);
    ownerMembershipId = mOwner.rows[0].id;

    const mLeader = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, reporting_manager_membership_id)
        VALUES ($1, $2, 'leader', 'ACTIVE', $3) RETURNING id;
    `, [USER_LEADER_ID, ORG_A_ID, ownerMembershipId]);
    leaderMembershipId = mLeader.rows[0].id;

    const mMgr = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, department, job_role, reporting_manager_membership_id)
        VALUES ($1, $2, 'manager_coordinator', 'ACTIVE', 'Design', 'Design Manager', $3) RETURNING id;
    `, [USER_MGR_ID, ORG_A_ID, leaderMembershipId]);
    mgrMembershipId = mMgr.rows[0].id;

    const mExec = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, department, job_role, reporting_manager_membership_id)
        VALUES ($1, $2, 'executive', 'ACTIVE', 'Design', 'Junior Designer', $3) RETURNING id;
    `, [USER_EXEC_ID, ORG_A_ID, mgrMembershipId]);
    execMembershipId = mExec.rows[0].id;

    const mIntern = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, department, job_role, expires_at)
        VALUES ($1, $2, 'intern', 'ACTIVE', 'Design', 'Design Intern', now() + interval '30 days') RETURNING id;
    `, [USER_INTERN_ID, ORG_A_ID]);
    internMembershipId = mIntern.rows[0].id;

    const mGuest = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, expires_at)
        VALUES ($1, $2, 'guest', 'ACTIVE', now() + interval '7 days') RETURNING id;
    `, [USER_GUEST_ID, ORG_A_ID]);
    guestMembershipId = mGuest.rows[0].id;

    const mCollab = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, expires_at)
        VALUES ($1, $2, 'collaborator', 'ACTIVE', now() + interval '14 days') RETURNING id;
    `, [USER_COLLAB_ID, ORG_A_ID]);
    collabMembershipId = mCollab.rows[0].id;

    const mStaff = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status)
        VALUES ($1, $2, 'client_servicing', 'ACTIVE') RETURNING id;
    `, [USER_STAFF_ID, PLATFORM_ORG_ID]);
    staffMembershipId = mStaff.rows[0].id;

    // Create a support grant for staff
    const grantRes = await adminPool.query(`
        INSERT INTO public.support_access_grants (
            staff_membership_id, target_organisation_id, reason, started_at, expires_at
        ) VALUES (
            $1, $2, 'Test support', now(), now() + interval '4 hours'
        ) RETURNING id;
    `, [staffMembershipId, ORG_A_ID]);
    supportGrantId = grantRes.rows[0].id;

    // Runtime Pool setup connected to the isolated test database
    runtimePool = new pg.Pool({
        ...RUNTIME_CONFIG,
        database: 'archscale_test_014'
    });
});

afterAll(async () => {
    if (runtimePool) await runtimePool.end().catch(() => {});
    if (adminPool) await adminPool.end().catch(() => {});
});

describe('Migration 014: Hierarchy, Invariants and Policies', () => {

    it('1. memberships: manager must belong to same organisation', async () => {
        // Create user & membership in Org B
        await adminPool.query(`
            INSERT INTO auth.users (id, email) VALUES ('30000000-0000-0000-0000-000000000099', 'other@b.test') ON CONFLICT DO NOTHING;
            INSERT INTO public.users (id, email, user_code) VALUES ('30000000-0000-0000-0000-000000000099', 'other@b.test', 'AS-OTH99') ON CONFLICT DO NOTHING;
        `);
        const otherMem = await adminPool.query(`
            INSERT INTO public.memberships (user_id, organisation_id, role_key, status)
            VALUES ('30000000-0000-0000-0000-000000000099', $1, 'leader', 'ACTIVE') RETURNING id;
        `, [ORG_B_ID]);

        // Attempt to assign Org B member as manager to an Org A member
        await expect(adminPool.query(`
            UPDATE public.memberships SET reporting_manager_membership_id = $1 WHERE id = $2;
        `, [otherMem.rows[0].id, execMembershipId])).rejects.toThrow(/same organisation|chk_membership_reporting_same_org|violates/i);
    });

    it('2. memberships: manager cannot be self', async () => {
        await expect(adminPool.query(`
            UPDATE public.memberships SET reporting_manager_membership_id = $1 WHERE id = $1;
        `, [mgrMembershipId])).rejects.toThrow(/not self|chk_membership_reporting_not_self|violates/i);
    });

    it('3. memberships: trigger rejects circular reporting cycles', async () => {
        // Currently: owner -> leader -> mgr -> exec
        // Attempting to set owner's manager to exec creates cycle: exec -> owner -> leader -> mgr -> exec
        await expect(adminPool.query(`
            UPDATE public.memberships SET reporting_manager_membership_id = $1 WHERE id = $2;
        `, [execMembershipId, ownerMembershipId])).rejects.toThrow(/cycle|circular/i);
    });

    it('4. memberships: manager must be in ACTIVE status', async () => {
        // Suspend mgr
        await adminPool.query(`UPDATE public.memberships SET status = 'SUSPENDED' WHERE id = $1;`, [mgrMembershipId]);

        // Attempt to assign suspended manager to intern
        await expect(adminPool.query(`
            UPDATE public.memberships SET reporting_manager_membership_id = $1 WHERE id = $2;
        `, [mgrMembershipId, internMembershipId])).rejects.toThrow(/active/i);

        // Restore mgr to ACTIVE
        await adminPool.query(`UPDATE public.memberships SET status = 'ACTIVE' WHERE id = $1;`, [mgrMembershipId]);
    });

    it('5. invitations: status enum, columns, and unique pending per (organisation, lower(email))', async () => {
        // Insert a Pending invitation (using invited_by_membership_id, no duplicate invited_by)
        const tokenHash = 'abc001hash';
        const invRes = await adminPool.query(`
            INSERT INTO public.invitations (
                organisation_id, email, token_hash, target_role_key, department, job_role,
                reporting_manager_membership_id, invited_by_membership_id, expires_at, status
            ) VALUES (
                $1, 'Invite.Test@Studio.test', $2, 'executive', 'Design', 'Junior Designer',
                $3, $4, now() + interval '7 days', 'Pending'
            ) RETURNING *;
        `, [ORG_A_ID, tokenHash, mgrMembershipId, ownerMembershipId]);

        const inv = invRes.rows[0];
        expect(inv.token_hash).toBe(tokenHash);
        expect(inv.target_role_key).toBe('executive');
        expect(inv.department).toBe('Design');
        expect(inv.job_role).toBe('Junior Designer');
        expect(inv.reporting_manager_membership_id).toBe(mgrMembershipId);
        expect(inv.invited_by_membership_id).toBe(ownerMembershipId);
        expect(inv.status).toBe('Pending');
        expect(inv.resend_count).toBe(0);

        // Confirm duplicate columns invited_by and used_at are dropped
        expect(inv).not.toHaveProperty('invited_by');
        expect(inv).not.toHaveProperty('used_at');

        // Duplicate insert with different casing on email must fail unique constraint
        await expect(adminPool.query(`
            INSERT INTO public.invitations (
                organisation_id, email, token_hash, target_role_key, invited_by_membership_id, expires_at, status
            ) VALUES (
                $1, 'invite.test@studio.test', 'abc002hash', 'executive', $2, now() + interval '7 days', 'Pending'
            );
        `, [ORG_A_ID, ownerMembershipId])).rejects.toThrow(/unique|uq_invitations_pending/i);

        // Invalid status spelling is rejected
        await expect(adminPool.query(`
            INSERT INTO public.invitations (
                organisation_id, email, token_hash, target_role_key, invited_by_membership_id, expires_at, status
            ) VALUES (
                $1, 'invalid.status@studio.test', 'abc003hash', 'executive', $2, now() + interval '7 days', 'PENDING'
            );
        `, [ORG_A_ID, ownerMembershipId])).rejects.toThrow(/invitations_status_check/i);
    });

    it('6. organisations.member_min_aal: default aal2, effective minimum never lowers aal2 role, member denied at aal1 in aal2 org', async () => {
        // Confirm default is aal2
        const freshOrgRes = await adminPool.query(`
            INSERT INTO public.organisations (name, portal, tenant_type_key, status)
            VALUES ('Fresh Org Defaults', 'subscriber', 'studio_owner', 'ACTIVE')
            RETURNING member_min_aal;
        `);
        expect(freshOrgRes.rows[0].member_min_aal).toBe('aal2');

        const adminClient = await adminPool.connect();
        try {
            // Test leader (role.min_aal = 'aal1', has org.members.read) in an org set to aal2:
            const leaderAal1CtxRes = await adminClient.query(`
                SELECT fn_create_access_context($1::uuid, 'sess_leader_aal1', $2::uuid, $3::uuid, 'aal1');
            `, [USER_LEADER_ID, ORG_A_ID, workspaceAId]);
            const leaderAal1CtxId = leaderAal1CtxRes.rows[0].fn_create_access_context;

            const leaderPrincipalAal1: VerifiedPrincipal = {
                id: USER_LEADER_ID,
                email: 'leader@studio.test',
                sessionId: 'sess_leader_aal1',
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };

            // Even though leader role.min_aal is aal1, org member_min_aal is aal2 -> decide() denies with AUTH_AAL
            const leaderDecision = await decide(adminClient, leaderPrincipalAal1, leaderAal1CtxId, 'org.members.read');
            expect(leaderDecision.allow).toBe(false);
            if (!leaderDecision.allow) {
                expect(leaderDecision.gateFailed).toBe(8);
                expect(leaderDecision.reasonCode).toBe('AUTH_AAL');
            }

            // Leader at aal2 in aal2 org is allowed
            const leaderAal2CtxRes = await adminClient.query(`
                SELECT fn_create_access_context($1::uuid, 'sess_leader_aal2', $2::uuid, $3::uuid, 'aal2');
            `, [USER_LEADER_ID, ORG_A_ID, workspaceAId]);
            const leaderAal2CtxId = leaderAal2CtxRes.rows[0].fn_create_access_context;
            const leaderPrincipalAal2: VerifiedPrincipal = {
                ...leaderPrincipalAal1,
                sessionId: 'sess_leader_aal2',
                aal: 'aal2'
            };
            const leaderDecisionAal2 = await decide(adminClient, leaderPrincipalAal2, leaderAal2CtxId, 'org.members.read');
            expect(leaderDecisionAal2.allow).toBe(true);

            // Setting org to aal1 by business_owner at aal2:
            const ownerAal2CtxRes = await adminClient.query(`
                SELECT fn_create_access_context($1::uuid, 'sess_owner_mfa', $2::uuid, $3::uuid, 'aal2');
            `, [USER_OWNER_ID, ORG_A_ID, workspaceAId]);
            const ownerAal2CtxId = ownerAal2CtxRes.rows[0].fn_create_access_context;

            // Set context via fn_set_app_context inside transaction
            await adminClient.query('BEGIN;');
            await adminClient.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [ownerAal2CtxId, USER_OWNER_ID, 'sess_owner_mfa']);
            await adminClient.query(`SELECT fn_set_organisation_mfa_requirement('aal1');`);
            await adminClient.query('COMMIT;');

            const orgCheck = await adminClient.query(`SELECT member_min_aal FROM public.organisations WHERE id = $1;`, [ORG_A_ID]);
            expect(orgCheck.rows[0].member_min_aal).toBe('aal1');

            // Verify: setting org to aal1 NEVER lowers business_owner (roles.min_aal = aal2)
            const ownerAal1CtxRes = await adminClient.query(`
                SELECT fn_create_access_context($1::uuid, 'sess_owner_aal1', $2::uuid, $3::uuid, 'aal1');
            `, [USER_OWNER_ID, ORG_A_ID, workspaceAId]);
            const ownerAal1CtxId = ownerAal1CtxRes.rows[0].fn_create_access_context;

            const ownerPrincipalAal1: VerifiedPrincipal = {
                id: USER_OWNER_ID,
                email: 'owner@studio.test',
                sessionId: 'sess_owner_aal1',
                aal: 'aal1',
                issuer: 'test',
                audience: 'test',
                expiresAt: Math.floor(Date.now() / 1000) + 3600
            };

            const ownerDecision = await decide(adminClient, ownerPrincipalAal1, ownerAal1CtxId, 'org.members.invite');
            expect(ownerDecision.allow).toBe(false);
            if (!ownerDecision.allow) {
                expect(ownerDecision.gateFailed).toBe(8);
                expect(ownerDecision.reasonCode).toBe('AUTH_AAL');
            }

            // Restore org to aal2
            await adminClient.query('BEGIN;');
            await adminClient.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [ownerAal2CtxId, USER_OWNER_ID, 'sess_owner_mfa']);
            await adminClient.query(`SELECT fn_set_organisation_mfa_requirement('aal2');`);
            await adminClient.query('COMMIT;');
        } finally {
            adminClient.release();
        }
    });

    it('7. access_profiles: attaches to any subscriber role; rejected if role or org mismatch; permissions merge', async () => {
        // Create an access profile for executive role
        const profRes = await adminPool.query(`
            INSERT INTO public.access_profiles (organisation_id, parent_role_key, role_key, name, description, is_active)
            VALUES ($1, 'executive', 'executive', 'Senior Executive Approver', 'Can approve member requests', true)
            RETURNING id;
        `, [ORG_A_ID]);
        const execProfileId = profRes.rows[0].id;

        // Attempting to attach this executive profile to an intern membership fails with trigger exception
        await expect(adminPool.query(`
            UPDATE public.memberships SET profile_id = $1 WHERE id = $2;
        `, [execProfileId, internMembershipId])).rejects.toThrow(/does not match membership role/i);

        // Attempting to attach profile from Org B to Org A membership fails
        const profBRes = await adminPool.query(`
            INSERT INTO public.access_profiles (organisation_id, parent_role_key, role_key, name, description, is_active)
            VALUES ($1, 'executive', 'executive', 'Org B Executive Profile', 'Desc', true)
            RETURNING id;
        `, [ORG_B_ID]);
        const orgBProfileId = profBRes.rows[0].id;

        await expect(adminPool.query(`
            UPDATE public.memberships SET profile_id = $1 WHERE id = $2;
        `, [orgBProfileId, execMembershipId])).rejects.toThrow(/does not match membership organisation/i);

        // Grant org.members.approve to execProfileId
        await adminPool.query(`
            INSERT INTO public.access_profile_permissions (profile_id, permission_key)
            VALUES ($1, 'org.members.approve')
            ON CONFLICT DO NOTHING;
        `, [execProfileId]);

        // Attach profile to matching exec membership
        await adminPool.query(`
            UPDATE public.memberships SET profile_id = $1 WHERE id = $2;
        `, [execProfileId, execMembershipId]);

        // Set context for exec on dedicated client inside transaction
        const execCtxRes = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, 'sess_exec_perms', $2::uuid, $3::uuid, 'aal2');
        `, [USER_EXEC_ID, ORG_A_ID, workspaceAId]);
        const execCtxId = execCtxRes.rows[0].fn_create_access_context;

        const client = await adminPool.connect();
        try {
            await client.query('BEGIN;');
            await client.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [execCtxId, USER_EXEC_ID, 'sess_exec_perms']);

            // Query effective permissions parameterless
            const permsRes = await client.query(`SELECT fn_get_effective_permissions() AS perms;`);
            const perms: string[] = permsRes.rows[0].perms;
            expect(perms).toContain('project.records.read');
            expect(perms).toContain('org.members.approve');

            // Querying membership belonging to Org B returns empty array
            const otherOrgMem = await client.query(`SELECT id FROM public.memberships WHERE organisation_id = $1 LIMIT 1;`, [ORG_B_ID]);
            const crossOrgRes = await client.query(`SELECT fn_get_effective_permissions($1::uuid) AS perms;`, [otherOrgMem.rows[0].id]);
            expect(crossOrgRes.rows[0].perms).toEqual([]);
            await client.query('COMMIT;');
        } finally {
            client.release();
        }
    });

    it('8. RLS: member sees only their own membership row; direct invitations SELECT is revoked and token_hash is never exposed', async () => {
        // Set context for intern on runtime client inside transaction
        const internCtxRes = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, 'sess_intern_rls', $2::uuid, $3::uuid, 'aal2');
        `, [USER_INTERN_ID, ORG_A_ID, workspaceAId]);
        const internCtxId = internCtxRes.rows[0].fn_create_access_context;

        // Add invitation
        await adminPool.query(`
            INSERT INTO public.invitations (
                organisation_id, email, token_hash, target_role_key, invited_by_membership_id, expires_at, status
            ) VALUES 
                ($1, 'intern@studio.test', 'hash_intern_rls', 'intern', $2, now() + interval '7 days', 'Pending'),
                ($1, 'secret@studio.test', 'hash_secret_rls', 'executive', $2, now() + interval '7 days', 'Pending')
            ON CONFLICT DO NOTHING;
        `, [ORG_A_ID, ownerMembershipId]);

        const client = await runtimePool.connect();
        try {
            await client.query('BEGIN;');
            await client.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [internCtxId, USER_INTERN_ID, 'sess_intern_rls']);

            // Direct SELECT on memberships returns ONLY intern's row
            const memRows = await client.query(`SELECT id, user_id FROM public.memberships;`);
            expect(memRows.rowCount).toBe(1);
            expect(memRows.rows[0].user_id).toBe(USER_INTERN_ID);

            // Direct SELECT on invitations by runtime client is completely REVOKED (fails with permission denied)
            await expect(client.query(`SELECT * FROM public.invitations;`)).rejects.toThrow(/permission denied/i);

            await client.query('COMMIT;');
        } finally {
            client.release();
        }

        // Test that fn_list_org_invitations never returns token_hash
        const ownerCtxRes = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, 'sess_owner_check_cols', $2::uuid, $3::uuid, 'aal2');
        `, [USER_OWNER_ID, ORG_A_ID, workspaceAId]);
        const ownerCtxId = ownerCtxRes.rows[0].fn_create_access_context;

        const ownerClient = await runtimePool.connect();
        try {
            await ownerClient.query('BEGIN;');
            await ownerClient.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [ownerCtxId, USER_OWNER_ID, 'sess_owner_check_cols']);

            const invRows = await ownerClient.query(`SELECT * FROM fn_list_org_invitations();`);
            expect(invRows.rowCount).toBeGreaterThan(0);
            const firstRow = invRows.rows[0];
            expect(firstRow).toHaveProperty('id');
            expect(firstRow).toHaveProperty('email');
            expect(firstRow).toHaveProperty('target_role_key');
            expect(firstRow).not.toHaveProperty('token_hash');
            expect(firstRow).not.toHaveProperty('token');

            await ownerClient.query('COMMIT;');
        } finally {
            ownerClient.release();
        }
    });

    it('9. definer listing functions: permission-gated (org.members.read / org.members.invite)', async () => {
        // Helper to test listing under a specific user context within a transaction
        async function runInUserContext<T>(userId: string, sessionId: string, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
            const ctxRes = await adminPool.query(`
                SELECT fn_create_access_context($1::uuid, $2, $3::uuid, $4::uuid, 'aal2');
            `, [userId, sessionId, ORG_A_ID, workspaceAId]);
            const ctxId = ctxRes.rows[0].fn_create_access_context;

            const client = await runtimePool.connect();
            try {
                await client.query('BEGIN;');
                await client.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [ctxId, userId, sessionId]);
                const result = await fn(client);
                await client.query('COMMIT;');
                return result;
            } catch (err) {
                await client.query('ROLLBACK;').catch(() => {});
                throw err;
            } finally {
                client.release();
            }
        }

        // 1. Guest: denied for both listing functions
        await expect(runInUserContext(USER_GUEST_ID, 'sess_guest_list', c => c.query(`SELECT * FROM fn_list_org_members();`)))
            .rejects.toThrow(/AUTH_PERMISSION_DENIED/i);
        await expect(runInUserContext(USER_GUEST_ID, 'sess_guest_list2', c => c.query(`SELECT * FROM fn_list_org_invitations();`)))
            .rejects.toThrow(/AUTH_PERMISSION_DENIED/i);

        // 2. Collaborator: denied for both
        await expect(runInUserContext(USER_COLLAB_ID, 'sess_collab_list', c => c.query(`SELECT * FROM fn_list_org_members();`)))
            .rejects.toThrow(/AUTH_PERMISSION_DENIED/i);
        await expect(runInUserContext(USER_COLLAB_ID, 'sess_collab_list2', c => c.query(`SELECT * FROM fn_list_org_invitations();`)))
            .rejects.toThrow(/AUTH_PERMISSION_DENIED/i);

        // 3. Intern: denied for both
        await expect(runInUserContext(USER_INTERN_ID, 'sess_intern_list', c => c.query(`SELECT * FROM fn_list_org_members();`)))
            .rejects.toThrow(/AUTH_PERMISSION_DENIED/i);
        await expect(runInUserContext(USER_INTERN_ID, 'sess_intern_list2', c => c.query(`SELECT * FROM fn_list_org_invitations();`)))
            .rejects.toThrow(/AUTH_PERMISSION_DENIED/i);

        // 4. Executive: denied for both
        await expect(runInUserContext(USER_EXEC_ID, 'sess_exec_list', c => c.query(`SELECT * FROM fn_list_org_members();`)))
            .rejects.toThrow(/AUTH_PERMISSION_DENIED/i);
        await expect(runInUserContext(USER_EXEC_ID, 'sess_exec_list2', c => c.query(`SELECT * FROM fn_list_org_invitations();`)))
            .rejects.toThrow(/AUTH_PERMISSION_DENIED/i);

        // 5. Leader: allowed for both
        const leaderMembers = await runInUserContext(USER_LEADER_ID, 'sess_leader_list', c => c.query(`SELECT * FROM fn_list_org_members();`));
        expect(leaderMembers.rowCount).toBeGreaterThanOrEqual(5);

        // Leader does not have org.members.invite by default, so invite list is denied
        await expect(runInUserContext(USER_LEADER_ID, 'sess_leader_list2', c => c.query(`SELECT * FROM fn_list_org_invitations();`)))
            .rejects.toThrow(/AUTH_PERMISSION_DENIED/i);

        // 6. Business Owner: allowed for both
        const ownerMembers = await runInUserContext(USER_OWNER_ID, 'sess_owner_list', c => c.query(`SELECT * FROM fn_list_org_members();`));
        expect(ownerMembers.rowCount).toBeGreaterThanOrEqual(5);
        const ownerInvs = await runInUserContext(USER_OWNER_ID, 'sess_owner_list2', c => c.query(`SELECT * FROM fn_list_org_invitations();`));
        expect(ownerInvs.rowCount).toBeGreaterThanOrEqual(1);

        // 7. Support context: allowed to read, denied on write
        const supCtxRes = await adminPool.query(`
            SELECT fn_create_access_context(
                $1::uuid, 'sess_staff_list', $2::uuid, $3::uuid, 'aal2', $4::uuid
            );
        `, [USER_STAFF_ID, ORG_A_ID, workspaceAId, supportGrantId]);
        const supCtxId = supCtxRes.rows[0].fn_create_access_context;

        const supClient = await runtimePool.connect();
        try {
            await supClient.query('BEGIN;');
            await supClient.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [supCtxId, USER_STAFF_ID, 'sess_staff_list']);
            const staffMembers = await supClient.query(`SELECT * FROM fn_list_org_members();`);
            expect(staffMembers.rowCount).toBeGreaterThanOrEqual(5);
            const staffInvs = await supClient.query(`SELECT * FROM fn_list_org_invitations();`);
            expect(staffInvs.rowCount).toBeGreaterThanOrEqual(1);

            // Support context denied on mutations
            await expect(supClient.query(`SELECT fn_set_organisation_mfa_requirement('aal1');`))
                .rejects.toThrow(/support contexts are read-only|AUTH_SUPPORT_READ_ONLY/i);
            await supClient.query('ROLLBACK;');
        } finally {
            supClient.release();
        }
    });

    it('10. auth_rate_limits: runtime direct DML revoked; fn_rate_limit_hit atomic and enforces limit', async () => {
        const client = await runtimePool.connect();
        try {
            // Direct DML from runtime must fail
            await expect(client.query(`SELECT * FROM public.auth_rate_limits;`)).rejects.toThrow(/permission denied/i);
            await expect(client.query(`INSERT INTO public.auth_rate_limits (key, action) VALUES ('k', 'signin');`)).rejects.toThrow(/permission denied/i);
            await expect(client.query(`DELETE FROM public.auth_rate_limits;`)).rejects.toThrow(/permission denied/i);

            // Invalid action is rejected by definer function
            await expect(client.query(`SELECT fn_rate_limit_hit('ip:10.0.0.1', 'invalid_action', 5, 60);`))
                .rejects.toThrow(/AUTH_RATE_LIMIT_INVALID_ACTION/i);

            // Single statement upsert respects max_attempts (5 attempts allowed, 6th denied)
            const rateKey = 'ip:192.168.1.100';
            for (let i = 1; i <= 5; i++) {
                const hitRes = await client.query<{ fn_rate_limit_hit: boolean }>(
                    `SELECT fn_rate_limit_hit($1, 'signin', 5, 60);`,
                    [rateKey]
                );
                expect(hitRes.rows[0].fn_rate_limit_hit).toBe(true);
            }

            // 6th attempt: exceeded
            const exceedRes = await client.query<{ fn_rate_limit_hit: boolean }>(
                `SELECT fn_rate_limit_hit($1, 'signin', 5, 60);`,
                [rateKey]
            );
            expect(exceedRes.rows[0].fn_rate_limit_hit).toBe(false);
        } finally {
            client.release();
        }

        // Concurrent atomic test: 10 parallel hits with max_attempts = 4 on a new key
        const concurrentKey = 'ip:10.99.99.99';
        const promises = Array.from({ length: 10 }, () =>
            adminPool.query<{ fn_rate_limit_hit: boolean }>(
                `SELECT fn_rate_limit_hit($1, 'signin', 4, 60);`,
                [concurrentKey]
            )
        );
        const results = await Promise.all(promises);
        const allowedCount = results.filter(r => r.rows[0].fn_rate_limit_hit === true).length;
        const deniedCount = results.filter(r => r.rows[0].fn_rate_limit_hit === false).length;

        expect(allowedCount).toBe(4);
        expect(deniedCount).toBe(6);
    });

    it('11. F2: Rate limit primary key creation fails on duplicate (key, action) pair without deduplication', async () => {
        // Create a temporary table mimicking auth_rate_limits with duplicate (key, action)
        await adminPool.query(`
            CREATE TEMPORARY TABLE test_rate_limits_dup (
                key TEXT,
                action TEXT
            );
            INSERT INTO test_rate_limits_dup (key, action) VALUES
                ('dup_key', 'signin'),
                ('dup_key', 'signin');
        `);

        // Adding primary key without deduplication must fail with unique violation (23505)
        await expect(adminPool.query(`
            ALTER TABLE test_rate_limits_dup ADD PRIMARY KEY (key, action);
        `)).rejects.toThrow(/could not create unique index|unique constraint|23505/i);
    });

    it('12. F3: fn_set_organisation_mfa_requirement gated by org.settings.manage permission and aal2', async () => {
        // Leader (who does not hold org.settings.manage) is denied with AUTH_PERMISSION_DENIED
        const leaderCtxRes = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, 'sess_lead_mfa_test', $2::uuid, $3::uuid, 'aal2');
        `, [USER_LEADER_ID, ORG_A_ID, workspaceAId]);
        const leaderCtxId = leaderCtxRes.rows[0].fn_create_access_context;

        const leaderClient = await runtimePool.connect();
        try {
            await leaderClient.query('BEGIN;');
            await leaderClient.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [leaderCtxId, USER_LEADER_ID, 'sess_lead_mfa_test']);
            await expect(leaderClient.query(`SELECT fn_set_organisation_mfa_requirement('aal1');`))
                .rejects.toThrow(/AUTH_PERMISSION_DENIED/i);
            await leaderClient.query('ROLLBACK;');
        } finally {
            leaderClient.release();
        }

        // Business owner at aal1 is denied with AUTH_AAL
        const ownerAal1Res = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, 'sess_owner_mfa_aal1', $2::uuid, $3::uuid, 'aal1');
        `, [USER_OWNER_ID, ORG_A_ID, workspaceAId]);
        const ownerAal1CtxId = ownerAal1Res.rows[0].fn_create_access_context;

        const ownerAal1Client = await runtimePool.connect();
        try {
            await ownerAal1Client.query('BEGIN;');
            await ownerAal1Client.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [ownerAal1CtxId, USER_OWNER_ID, 'sess_owner_mfa_aal1']);
            await expect(ownerAal1Client.query(`SELECT fn_set_organisation_mfa_requirement('aal1');`))
                .rejects.toThrow(/AUTH_AAL/i);
            await ownerAal1Client.query('ROLLBACK;');
        } finally {
            ownerAal1Client.release();
        }

        // Business owner at aal2 is ALLOWED
        const ownerAal2Res = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, 'sess_owner_mfa_aal2', $2::uuid, $3::uuid, 'aal2');
        `, [USER_OWNER_ID, ORG_A_ID, workspaceAId]);
        const ownerAal2CtxId = ownerAal2Res.rows[0].fn_create_access_context;

        const ownerAal2Client = await runtimePool.connect();
        try {
            await ownerAal2Client.query('BEGIN;');
            await ownerAal2Client.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [ownerAal2CtxId, USER_OWNER_ID, 'sess_owner_mfa_aal2']);
            const res = await ownerAal2Client.query(`SELECT fn_set_organisation_mfa_requirement('aal1');`);
            expect(res.rowCount).toBe(1);
            await ownerAal2Client.query('COMMIT;');
        } finally {
            ownerAal2Client.release();
        }
    });

    it('13. F4: Support context without platform.support.read is denied in fn_list_org_members and fn_list_org_invitations', async () => {
        // Create an untrusted staff user without platform.support.read permission
        const UNTRUSTED_STAFF_ID = '30000000-0000-0000-0000-000000000099';
        await adminPool.query(`INSERT INTO auth.users (id, email) VALUES ($1, 'untrusted@platform.test') ON CONFLICT DO NOTHING;`, [UNTRUSTED_STAFF_ID]);
        await adminPool.query(`INSERT INTO public.users (id, user_code, email) VALUES ($1, 'AS-UNTRUST', 'untrusted@platform.test') ON CONFLICT DO NOTHING;`, [UNTRUSTED_STAFF_ID]);
        const devMemRes = await adminPool.query(`
            INSERT INTO public.memberships (user_id, organisation_id, role_key, status)
            VALUES ($1, $2, 'developer', 'ACTIVE')
            RETURNING id;
        `, [UNTRUSTED_STAFF_ID, PLATFORM_ORG_ID]);
        const devMemId = devMemRes.rows[0].id;

        const grantRes = await adminPool.query(`
            INSERT INTO public.support_access_grants (staff_membership_id, target_organisation_id, reason, expires_at)
            VALUES ($1, $2, 'Investigating bug', now() + interval '2 hours') RETURNING id;
        `, [devMemId, ORG_A_ID]);
        const badGrantId = grantRes.rows[0].id;

        const badSupCtxRes = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, 'sess_bad_staff', $2::uuid, $3::uuid, 'aal2', $4::uuid);
        `, [UNTRUSTED_STAFF_ID, ORG_A_ID, workspaceAId, badGrantId]);
        const badSupCtxId = badSupCtxRes.rows[0].fn_create_access_context;

        const badClient = await runtimePool.connect();
        try {
            await badClient.query('BEGIN;');
            await badClient.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [badSupCtxId, UNTRUSTED_STAFF_ID, 'sess_bad_staff']);

            // Expect rejection because developer role lacks platform.support.read
            await expect(badClient.query(`SELECT * FROM fn_list_org_members();`))
                .rejects.toThrow(/AUTH_PERMISSION_DENIED: Support context requires platform.support.read/i);

            await badClient.query('ROLLBACK;').catch(() => {});
            await badClient.query('BEGIN;');
            await badClient.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [badSupCtxId, UNTRUSTED_STAFF_ID, 'sess_bad_staff']);

            await expect(badClient.query(`SELECT * FROM fn_list_org_invitations();`))
                .rejects.toThrow(/AUTH_PERMISSION_DENIED: Support context requires platform.support.read/i);

            await badClient.query('ROLLBACK;').catch(() => {});
        } finally {
            await badClient.query('ROLLBACK;').catch(() => {});
            badClient.release();
        }
    });

    it('14. F5: fn_get_effective_permissions(membership_id) enforces org.members.read and active status', async () => {
        // Intern inspecting own permissions succeeds
        const internCtxRes = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, 'sess_int_eff', $2::uuid, $3::uuid, 'aal1');
        `, [USER_INTERN_ID, ORG_A_ID, workspaceAId]);
        const internCtxId = internCtxRes.rows[0].fn_create_access_context;

        const internClient = await runtimePool.connect();
        try {
            await internClient.query('BEGIN;');
            await internClient.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [internCtxId, USER_INTERN_ID, 'sess_int_eff']);

            // Own permissions
            const ownPermsRes = await internClient.query<{ fn_get_effective_permissions: string[] }>(
                `SELECT fn_get_effective_permissions();`
            );
            expect(ownPermsRes.rows[0].fn_get_effective_permissions).toBeInstanceOf(Array);

            // Intern inspecting leader's permissions without org.members.read returns empty array {}
            const otherPermsRes = await internClient.query<{ fn_get_effective_permissions: string[] }>(
                `SELECT fn_get_effective_permissions($1::uuid);`, [leaderMembershipId]
            );
            expect(otherPermsRes.rows[0].fn_get_effective_permissions).toEqual([]);

            await internClient.query('COMMIT;');
        } finally {
            internClient.release();
        }

        // Leader (with org.members.read) inspecting an expired or suspended membership gets empty array {}
        const leaderCtxRes = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, 'sess_lead_eff', $2::uuid, $3::uuid, 'aal1');
        `, [USER_LEADER_ID, ORG_A_ID, workspaceAId]);
        const leaderCtxId = leaderCtxRes.rows[0].fn_create_access_context;

        // Temporarily suspend intern membership
        await adminPool.query(`UPDATE public.memberships SET status = 'SUSPENDED' WHERE id = $1;`, [internMembershipId]);

        const leaderClient = await runtimePool.connect();
        try {
            await leaderClient.query('BEGIN;');
            await leaderClient.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [leaderCtxId, USER_LEADER_ID, 'sess_lead_eff']);

            const suspendedPermsRes = await leaderClient.query<{ fn_get_effective_permissions: string[] }>(
                `SELECT fn_get_effective_permissions($1::uuid);`, [internMembershipId]
            );
            expect(suspendedPermsRes.rows[0].fn_get_effective_permissions).toEqual([]);

            await leaderClient.query('COMMIT;');
        } finally {
            leaderClient.release();
            // Restore intern membership status
            await adminPool.query(`UPDATE public.memberships SET status = 'ACTIVE' WHERE id = $1;`, [internMembershipId]);
        }
    });

    it('15. A3: Invitations Engine Security Definer functions lifecycle', async () => {
        const ownerCtxRes = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, 'sess_owner_inv_test', $2::uuid, $3::uuid, 'aal2');
        `, [USER_OWNER_ID, ORG_A_ID, workspaceAId]);
        const ownerCtxId = ownerCtxRes.rows[0].fn_create_access_context;

        const client = await runtimePool.connect();
        let invId: string;
        const testRawToken = 'secret-test-token-123456789012345678901234';

        try {
            await client.query('BEGIN;');
            await client.query(`SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);`, [ownerCtxId, USER_OWNER_ID, 'sess_owner_inv_test']);

            // 1. Create invitation for intern (with expiry and manager)
            const crypto = await import('crypto');
            const tokenHash = crypto.createHash('sha256').update(testRawToken).digest('hex');

            const createRes = await client.query<{ fn_create_invitation: string }>(`
                SELECT fn_create_invitation(
                    'invitee.one@studio.test',
                    'intern',
                    NULL,
                    'Engineering',
                    'Junior Intern',
                    $1::uuid,
                    now() + interval '30 days',
                    $2
                );
            `, [mgrMembershipId, tokenHash]);
            invId = createRes.rows[0].fn_create_invitation;
            expect(invId).toBeDefined();

            // 2. Mark invitation sent
            const sentRes = await client.query<{ fn_mark_invitation_sent: boolean }>(`
                SELECT fn_mark_invitation_sent($1::uuid);
            `, [invId]);
            expect(sentRes.rows[0].fn_mark_invitation_sent).toBe(true);

            // 3. Resend invitation with rate limit check
            const newHash = crypto.createHash('sha256').update('new-token-999').digest('hex');
            const resendRes = await client.query<{ fn_resend_invitation: boolean }>(`
                SELECT fn_resend_invitation($1::uuid, $2);
            `, [invId, newHash]);
            expect(resendRes.rows[0].fn_resend_invitation).toBe(true);

            await client.query('COMMIT;');
        } finally {
            client.release();
        }

        // Re-hash back to testRawToken for acceptance test (after transaction commit)
        await adminPool.query(`UPDATE public.invitations SET token_hash = $1, status = 'Sent' WHERE id = $2;`, [
            (await import('crypto')).createHash('sha256').update(testRawToken).digest('hex'),
            invId
        ]);

        // 4. Accept invitation by invitee user
        const INVITEE_USER_ID = '30000000-0000-0000-0000-000000000077';
        await adminPool.query(`INSERT INTO auth.users (id, email) VALUES ($1, 'invitee.one@studio.test') ON CONFLICT DO NOTHING;`, [INVITEE_USER_ID]);
        await adminPool.query(`INSERT INTO public.users (id, user_code, email) VALUES ($1, 'AS-INV01', 'invitee.one@studio.test') ON CONFLICT DO NOTHING;`, [INVITEE_USER_ID]);

        // Wrong token rejected
        await expect(adminPool.query(`SELECT fn_accept_invitation('wrong-token', $1::uuid);`, [INVITEE_USER_ID]))
            .rejects.toThrow(/AUTH_INVITATION_NOT_FOUND/i);

        // Wrong email rejected
        await expect(adminPool.query(`SELECT fn_accept_invitation($1, $2::uuid);`, [testRawToken, USER_EXEC_ID]))
            .rejects.toThrow(/AUTH_INVITATION_EMAIL_MISMATCH/i);

        // Correct acceptance creates membership with copied department, job_role, and reporting manager
        const acceptRes = await adminPool.query<{ fn_accept_invitation: string }>(`
            SELECT fn_accept_invitation($1, $2::uuid);
        `, [testRawToken, INVITEE_USER_ID]);
        const newMemId = acceptRes.rows[0].fn_accept_invitation;
        expect(newMemId).toBeDefined();

        const memCheck = await adminPool.query(`
            SELECT role_key, department, job_role, reporting_manager_membership_id, status
            FROM public.memberships WHERE id = $1;
        `, [newMemId]);
        expect(memCheck.rows[0].role_key).toBe('intern');
        expect(memCheck.rows[0].department).toBe('Engineering');
        expect(memCheck.rows[0].job_role).toBe('Junior Intern');
        expect(memCheck.rows[0].reporting_manager_membership_id).toBe(mgrMembershipId);
        expect(memCheck.rows[0].status).toBe('ACTIVE');

        // Accepting a second time fails because status is Accepted
        await expect(adminPool.query(`SELECT fn_accept_invitation($1, $2::uuid);`, [testRawToken, INVITEE_USER_ID]))
            .rejects.toThrow(/AUTH_INVITATION_INVALID_STATUS/i);

        // B0.2: Audit entry exists with correct organisation_id and actor
        const auditRes = await adminPool.query(`
            SELECT action, actor_user_id, organisation_id, target_entity, target_id
            FROM public.audit_logs
            WHERE action = 'invitation.accepted' AND target_id = $1::text;
        `, [invId]);
        expect(auditRes.rows.length).toBe(1);
        expect(auditRes.rows[0].actor_user_id).toBe(INVITEE_USER_ID);
        expect(auditRes.rows[0].organisation_id).toBe(ORG_A_ID);
        expect(auditRes.rows[0].target_entity).toBe('invitations');

        // B0.2: Runtime role cannot insert an 'invitation.accepted' row through fn_audit_append without context
        const runtimePool = new pg.Pool(RUNTIME_CONFIG);
        try {
            await expect(runtimePool.query(
                `SELECT fn_audit_append('invitation.accepted', 'invitations', 'forged-id');`
            )).rejects.toThrow(/AUTH_AUDIT_UNAUTHORIZED/i);
        } finally {
            await runtimePool.end();
        }
    });
});
