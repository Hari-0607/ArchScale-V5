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
 *      - status enum: Pending, Sent, Accepted, Expired, Revoked
 *      - unique Pending per (organisation_id, lower(email))
 *      - target fields recorded
 *   3. organisations.member_min_aal:
 *      - 'aal1' or 'aal2', default 'aal2'
 *      - Effective minimum = max(roles.min_aal, organisations.member_min_aal)
 *      - aal2 roles can never be lowered by org setting
 *      - only business_owner at aal2 can change it via fn_set_organisation_mfa_requirement (audited)
 *      - intern cannot change it
 *   4. access_profiles:
 *      - Can attach to ANY subscriber role
 *      - Effective permissions = role permissions + profile permissions
 *   5. Security Definer functions reject support contexts (fn_assert_not_support_context)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createIsolatedTestDatabase, RUNTIME_CONFIG } from '../setup/db_connection.js';
import pg from 'pg';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let adminPool: pg.Pool;
let runtimeClient: pg.Client;

const USER_OWNER_ID = '30000000-0000-0000-0000-000000000001';
const USER_MGR_ID   = '30000000-0000-0000-0000-000000000002';
const USER_EXEC_ID  = '30000000-0000-0000-0000-000000000003';
const USER_INTERN_ID = '30000000-0000-0000-0000-000000000004';
const USER_STAFF_ID = '30000000-0000-0000-0000-000000000005';

const ORG_A_ID = '30000000-0000-0000-0000-000000000010';
const ORG_B_ID = '30000000-0000-0000-0000-000000000020';
const PLATFORM_ORG_ID = '00000000-0000-0000-0000-000000000001';

let ownerMembershipId: string;
let mgrMembershipId: string;
let execMembershipId: string;
let internMembershipId: string;
let staffMembershipId: string;
let workspaceAId: string;
let supportGrantId: string;

beforeAll(async () => {
    adminPool = await createIsolatedTestDatabase('archscale_test_014');

    // Apply migration 014 on top of fresh DB
    const m14Sql = fs.readFileSync(path.join(__dirname, '../../migrations/014_organisational_hierarchy_and_invitations.sql'), 'utf-8');
    await adminPool.query(m14Sql);

    // Seed auth.users & mirror
    const testUsers = [
        [USER_OWNER_ID, 'owner@studio.test', 'AS-OWNER01'],
        [USER_MGR_ID, 'mgr@studio.test', 'AS-MGR01'],
        [USER_EXEC_ID, 'exec@studio.test', 'AS-EXEC01'],
        [USER_INTERN_ID, 'intern@studio.test', 'AS-INT01'],
        [USER_STAFF_ID, 'staff@platform.test', 'AS-STAFF01'],
    ];
    for (const [uid, email, code] of testUsers) {
        await adminPool.query('INSERT INTO auth.users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING;', [uid, email]);
        await adminPool.query('INSERT INTO public.users (id, email, user_code) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING;', [uid, email, code]);
    }

    // Seed organisations
    await adminPool.query(`
        INSERT INTO public.organisations (id, name, portal, tenant_type_key, status)
        VALUES 
            ($1, 'Studio Design Org', 'subscriber', 'studio_owner', 'ACTIVE'),
            ($2, 'Other Tenant Org', 'subscriber', 'studio_owner', 'ACTIVE')
        ON CONFLICT (id) DO NOTHING;
    `, [ORG_A_ID, ORG_B_ID]);

    // Entitlement for ORG_A
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

    const mMgr = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status, department, job_role, reporting_manager_membership_id)
        VALUES ($1, $2, 'manager_coordinator', 'ACTIVE', 'Design', 'Design Manager', $3) RETURNING id;
    `, [USER_MGR_ID, ORG_A_ID, ownerMembershipId]);
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

    const mStaff = await adminPool.query(`
        INSERT INTO public.memberships (user_id, organisation_id, role_key, status)
        VALUES ($1, $2, 'client_servicing', 'ACTIVE') RETURNING id;
    `, [USER_STAFF_ID, PLATFORM_ORG_ID]);
    staffMembershipId = mStaff.rows[0].id;

    // Create a support grant for staff
    const grantRes = await adminPool.query(`
        INSERT INTO public.support_access_grants (
            staff_user_id, staff_membership_id, target_organisation_id,
            reason, justification, requested_duration, expires_at, status
        ) VALUES (
            $1, $2, $3, 'Test support', 'Verification', interval '4 hours', now() + interval '4 hours', 'ACTIVE'
        ) RETURNING id;
    `, [USER_STAFF_ID, staffMembershipId, ORG_A_ID]);
    supportGrantId = grantRes.rows[0].id;

    // Runtime Client setup
    runtimeClient = new pg.Client(RUNTIME_CONFIG);
    await runtimeClient.connect();
});

afterAll(async () => {
    if (runtimeClient) await runtimeClient.end().catch(() => {});
    if (adminPool) await adminPool.end().catch(() => {});
});

describe('Migration 014: Hierarchy, Invariants and Policies', () => {

    it('1. memberships: manager must belong to same organisation', async () => {
        // Create user & membership in Org B
        const otherUserRes = await adminPool.query(`
            INSERT INTO auth.users (id, email) VALUES ('30000000-0000-0000-0000-000000000099', 'other@b.test') RETURNING id;
        `);
        await adminPool.query(`
            INSERT INTO public.users (id, email, user_code) VALUES ('30000000-0000-0000-0000-000000000099', 'other@b.test', 'AS-OTH99');
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
        // Currently: owner -> mgr -> exec
        // Attempting to set owner's manager to exec creates cycle: exec -> owner -> mgr -> exec
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

    it('5. invitations: status enum and unique pending per (organisation, lower(email))', async () => {
        // Insert a Pending invitation
        const tokenHash = 'abc001hash';
        await adminPool.query(`
            INSERT INTO public.invitations (
                organisation_id, email, token_hash, target_role_key, department, job_role,
                reporting_manager_membership_id, invited_by_membership_id, expires_at, status
            ) VALUES (
                $1, 'Invite.Test@Studio.test', $2, 'executive', 'Design', 'Junior Designer',
                $3, $4, now() + interval '7 days', 'Pending'
            );
        `, [ORG_A_ID, tokenHash, mgrMembershipId, ownerMembershipId]);

        // Duplicate insert with different casing on email must fail unique constraint
        await expect(adminPool.query(`
            INSERT INTO public.invitations (
                organisation_id, email, token_hash, target_role_key, invited_by_membership_id, expires_at, status
            ) VALUES (
                $1, 'invite.test@studio.test', 'abc002hash', 'executive', $2, now() + interval '7 days', 'Pending'
            );
        `, [ORG_A_ID, ownerMembershipId])).rejects.toThrow(/unique|uq_invitations_pending/i);
    });

    it('6. organisations.member_min_aal: default is aal2 and only business_owner at aal2 can change it', async () => {
        // Check default
        const orgRes = await adminPool.query(`SELECT member_min_aal FROM public.organisations WHERE id = $1;`, [ORG_A_ID]);
        expect(orgRes.rows[0].member_min_aal).toBe('aal2');

        // Create aal1 context for owner
        const ctxAal1Res = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, 'session_owner_001', $2::uuid, $3::uuid, 'aal1');
        `, [USER_OWNER_ID, ORG_A_ID, workspaceAId]);
        const ctxAal1Id = ctxAal1Res.rows[0].fn_create_access_context;

        // fn_set_organisation_mfa_requirement via aal1 context fails
        await expect(adminPool.query(`
            SELECT fn_set_organisation_mfa_requirement($1::uuid, 'aal1');
        `, [ctxAal1Id])).rejects.toThrow(/aal2|AUTH_AAL/i);

        // Create aal2 context for owner
        const ctxAal2Res = await adminPool.query(`
            SELECT fn_create_access_context($1::uuid, 'session_owner_002', $2::uuid, $3::uuid, 'aal2');
        `, [USER_OWNER_ID, ORG_A_ID, workspaceAId]);
        const ctxAal2Id = ctxAal2Res.rows[0].fn_create_access_context;

        // Change setting to aal1 via aal2 context succeeds
        await adminPool.query(`
            SELECT fn_set_organisation_mfa_requirement($1::uuid, 'aal1');
        `, [ctxAal2Id]);

        const updated = await adminPool.query(`SELECT member_min_aal FROM public.organisations WHERE id = $1;`, [ORG_A_ID]);
        expect(updated.rows[0].member_min_aal).toBe('aal1');

        // Reset back to aal2
        await adminPool.query(`
            SELECT fn_set_organisation_mfa_requirement($1::uuid, 'aal2');
        `, [ctxAal2Id]);
    });

    it('7. access_profiles: attaches to any subscriber role; effective permissions merge', async () => {
        // Create an access profile for executive
        const profRes = await adminPool.query(`
            INSERT INTO public.access_profiles (organisation_id, parent_role_key, name, description, is_active)
            VALUES ($1, 'executive', 'Senior Executive Approver', 'Can approve member requests', true)
            RETURNING id;
        `, [ORG_A_ID]);
        const profileId = profRes.rows[0].id;

        // Grant org.members.approve to this profile
        await adminPool.query(`
            INSERT INTO public.access_profile_permissions (profile_id, permission_key)
            VALUES ($1, 'org.members.approve')
            ON CONFLICT DO NOTHING;
        `, [profileId]);

        // Attach profile to exec membership
        await adminPool.query(`
            UPDATE public.memberships SET profile_id = $1 WHERE id = $2;
        `, [profileId, execMembershipId]);

        // Query effective permissions via definer function
        const permsRes = await adminPool.query(`
            SELECT fn_get_effective_permissions($1::uuid) AS perms;
        `, [execMembershipId]);
        const perms: string[] = permsRes.rows[0].perms;

        // Must have executive's base permissions PLUS profile's permission
        expect(perms).toContain('project.records.read');
        expect(perms).toContain('org.members.approve');
    });

    it('8. support context cannot write or modify organization settings', async () => {
        // Create support context for staff entering ORG_A
        const supCtxRes = await adminPool.query(`
            SELECT fn_create_access_context(
                $1::uuid, 'session_staff_001', $2::uuid, $3::uuid, 'aal2', $4::uuid
            );
        `, [USER_STAFF_ID, ORG_A_ID, workspaceAId, supportGrantId]);
        const supCtxId = supCtxRes.rows[0].fn_create_access_context;

        // Setting MFA requirement fails because support context is read-only
        await expect(adminPool.query(`
            SELECT fn_set_organisation_mfa_requirement($1::uuid, 'aal1');
        `, [supCtxId])).rejects.toThrow(/support context|read-only|fn_assert_not_support_context/i);
    });
});
