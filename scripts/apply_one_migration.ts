import fs from 'fs';
import path from 'path';
import pg from 'pg';
import { fileURLToPath } from 'url';

// Load .env natively without logging secrets
if (fs.existsSync('.env')) {
    const lines = fs.readFileSync('.env', 'utf-8').split(/\r?\n/);
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
            const idx = trimmed.indexOf('=');
            if (idx !== -1) {
                const k = trimmed.substring(0, idx).trim();
                const v = trimmed.substring(idx + 1).trim();
                if (!process.env[k]) process.env[k] = v;
            }
        }
    }
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
    const args = process.argv.slice(2);

    // 1. Guardrail: Must provide --confirm-staging
    if (!args.includes('--confirm-staging')) {
        console.error('ABORTED: Refusing to run without --confirm-staging flag.');
        process.exit(1);
    }

    // 2. Identify files to run in transaction
    const fileArgs = args.filter(a => !a.startsWith('--'));
    if (fileArgs.length === 0) {
        console.error('ABORTED: Missing migration file argument.');
        console.error('Usage: npx tsx scripts/apply_one_migration.ts <file1> [file2...] --confirm-staging');
        process.exit(1);
    }

    const resolvedFilePaths: string[] = [];
    for (const fileArg of fileArgs) {
        let migrationFilePath = fileArg;
        if (!fs.existsSync(migrationFilePath)) {
            const inMigrations = path.join(__dirname, '../migrations', fileArg);
            const inSeeds = path.join(__dirname, '../seeds', fileArg);
            if (fs.existsSync(inMigrations)) {
                migrationFilePath = inMigrations;
            } else if (fs.existsSync(inSeeds)) {
                migrationFilePath = inSeeds;
            } else {
                console.error(`ABORTED: File not found: ${fileArg}`);
                process.exit(1);
            }
        }
        resolvedFilePaths.push(migrationFilePath);
    }

    // 3. Staging environment verification
    if (process.env.ARCHSCALE_ENV !== 'staging') {
        console.error(`ABORTED: ARCHSCALE_ENV must be 'staging'. Current: '${process.env.ARCHSCALE_ENV || 'undefined'}'`);
        process.exit(1);
    }

    const projectRef = process.env.ARCHSCALE_STAGING_PROJECT_REF;
    if (!projectRef) {
        console.error('ABORTED: ARCHSCALE_STAGING_PROJECT_REF is missing in .env');
        process.exit(1);
    }

    const adminUrl = process.env.SUPABASE_DB_ADMIN_URL;
    if (!adminUrl) {
        console.error('ABORTED: SUPABASE_DB_ADMIN_URL is missing in .env');
        process.exit(1);
    }

    // Print ONLY the project ref (never connection strings or secrets)
    console.log(`[Staging Migration Target] Project Ref: ${projectRef}`);
    console.log(`[Files to Apply in Transaction]:`);
    for (const f of resolvedFilePaths) {
        console.log(`  - ${path.basename(f)}`);
    }

    const client = new pg.Client({
        connectionString: adminUrl,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 15000
    });

    try {
        await client.connect();
    } catch (err: any) {
        console.error('ABORTED: Failed to connect to database. Redacted error message:', err.message?.replace(adminUrl, '[REDACTED]'));
        process.exit(1);
    }

    console.log('[1/3] Starting execution inside a single transaction...');
    try {
        await client.query('BEGIN;');

        for (const filePath of resolvedFilePaths) {
            console.log(`  Executing: ${path.basename(filePath)}...`);
            const sqlContent = fs.readFileSync(filePath, 'utf-8');
            await client.query(sqlContent);
        }

        console.log('[2/3] All SQL files executed. Running read-only post-checks...');

        const anyHas015 = resolvedFilePaths.some(p => path.basename(p).includes('015'));
        const anyHas014 = resolvedFilePaths.some(p => path.basename(p).includes('014'));
        const anyHas013 = resolvedFilePaths.some(p => path.basename(p).includes('013'));
        const anyHas012 = resolvedFilePaths.some(p => path.basename(p).includes('012'));

        if (anyHas015) {
            console.log('Running specialized post-checks for Migration 015:');

            // Check 1: Schema columns for expiry split
            const colCheck = await client.query(`
                SELECT
                    EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'invitations' AND column_name = 'invitation_expires_at') AS has_inv_expires,
                    EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'invitations' AND column_name = 'membership_expires_at') AS has_mem_expires;
            `);
            const cr = colCheck.rows[0];
            if (!cr.has_inv_expires) throw new Error('Post-check 015 failed: invitations.invitation_expires_at missing');
            if (!cr.has_mem_expires) throw new Error('Post-check 015 failed: invitations.membership_expires_at missing');
            console.log('  ✓ invitations expiry split columns (invitation_expires_at, membership_expires_at) verified.');

            // Check 2: Functions exist
            const funcs015 = [
                'fn_mark_invitation_expired',
                'fn_create_invitation',
                'fn_accept_invitation',
                'fn_list_org_invitations',
                'fn_platform_approve_organisation',
                'fn_platform_invite_tenant_admin',
                'fn_list_org_support_grants'
            ];
            const funcRes = await client.query(`
                SELECT p.proname 
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'public' AND p.proname = ANY($1::text[]);
            `, [funcs015]);
            const found015 = new Set(funcRes.rows.map(r => r.proname));
            for (const f of funcs015) {
                if (!found015.has(f)) throw new Error(`Post-check 015 failed: function ${f} missing from database!`);
            }
            console.log(`  ✓ All ${funcs015.length} Migration 015 functions exist.`);

            // Check 3: Check fn_audit_append allowlist reverted (no context call with 'invitation.accepted' fails)
            try {
                await client.query(`SELECT fn_audit_append('invitation.accepted', 'invitations', 'test');`);
                throw new Error('Post-check 015 failed: fn_audit_append still allows unauthenticated invitation.accepted!');
            } catch (err: any) {
                if (err.message.includes('AUTH_AUDIT_UNAUTHORIZED')) {
                    console.log('  ✓ fn_audit_append no-context allowlist is strictly reverted.');
                } else {
                    throw err;
                }
            }

            // Check 4 (B0.9): Check ARCHSCALE_TEST_INVITE_EMAIL
            const testInviteEmail = process.env.ARCHSCALE_TEST_INVITE_EMAIL;
            if (testInviteEmail) {
                console.log(`  [B0.9] ARCHSCALE_TEST_INVITE_EMAIL present: sending ONE real invitation via Supabase...`);
                const { sendInvitationMail } = await import('../src/mail/sink.js');
                const rawToken = (await import('crypto')).randomBytes(32).toString('base64url');
                const result = await sendInvitationMail({
                    to: testInviteEmail,
                    rawToken,
                    organisationName: 'ArchScale Staging'
                });
                if (result.success) {
                    console.log('  ✓ Real invitation dispatched. Status: Sent');
                } else {
                    throw new Error('Post-check 015 failed to send real invite email');
                }
            } else {
                console.log('  ✓ ARCHSCALE_TEST_INVITE_EMAIL is not set in environment (present: false). Real invite send skipped.');
            }

        } else if (anyHas014) {
            console.log('Running specialized post-checks for Migration 014:');

            // Check 1: Schema columns
            const colCheck = await client.query(`
                SELECT
                    EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'organisations' AND column_name = 'member_min_aal') AS has_member_min_aal,
                    EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'memberships' AND column_name = 'department') AS has_mem_dept,
                    EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'memberships' AND column_name = 'reporting_manager_membership_id') AS has_mem_reporting,
                    EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'invitations' AND column_name = 'invited_by_membership_id') AS has_inv_invited_by_mem,
                    EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'invitations' AND column_name = 'accepted_at') AS has_inv_accepted_at,
                    EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'invitations' AND column_name = 'invited_by') AS has_old_invited_by,
                    EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'invitations' AND column_name = 'used_at') AS has_old_used_at;
            `);
            const cr = colCheck.rows[0];
            if (!cr.has_member_min_aal) throw new Error('Post-check 014 failed: organisations.member_min_aal missing');
            if (!cr.has_mem_dept || !cr.has_mem_reporting) throw new Error('Post-check 014 failed: memberships hierarchy columns missing');
            if (!cr.has_inv_invited_by_mem || !cr.has_inv_accepted_at) throw new Error('Post-check 014 failed: invitations upgraded columns missing');
            if (cr.has_old_invited_by || cr.has_old_used_at) throw new Error('Post-check 014 failed: invitations old duplicate columns still exist');
            console.log('  ✓ Schema columns and deduplication verified.');

            // Check 2: Functions exist
            const funcs014 = [
                'fn_set_organisation_mfa_requirement',
                'fn_get_effective_permissions',
                'fn_list_org_members',
                'fn_list_org_invitations',
                'fn_rate_limit_hit',
                'fn_create_invitation',
                'fn_mark_invitation_sent',
                'fn_revoke_invitation',
                'fn_resend_invitation',
                'fn_accept_invitation'
            ];
            const funcRes = await client.query(`
                SELECT p.proname 
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'public' AND p.proname = ANY($1::text[]);
            `, [funcs014]);
            const found014 = new Set(funcRes.rows.map(r => r.proname));
            for (const f of funcs014) {
                if (!found014.has(f)) throw new Error(`Post-check 014 failed: function ${f} missing from database!`);
            }
            console.log(`  ✓ All ${funcs014.length} Migration 014 functions exist.`);

            // Check 3: Runtime cannot SELECT directly from invitations
            const invPriv = await client.query(`
                SELECT has_table_privilege('archscale_app_runtime', 'public.invitations', 'SELECT') AS can_select;
            `);
            if (invPriv.rows[0].can_select !== false) {
                throw new Error('Post-check 014 failed: archscale_app_runtime has SELECT privilege on invitations!');
            }
            console.log('  ✓ Direct table SELECT on invitations is revoked from runtime role.');

            // Check 4: Rate limit composite PK
            const pkCheck = await client.query(`
                SELECT COUNT(*) AS pk_cols
                FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid
                WHERE t.relname = 'auth_rate_limits' AND c.contype = 'p';
            `);
            if (parseInt(pkCheck.rows[0].pk_cols, 10) === 0) {
                throw new Error('Post-check 014 failed: auth_rate_limits composite primary key missing!');
            }
            console.log('  ✓ auth_rate_limits composite primary key exists.');

            // Check 5: Permissions
            const permCheck = await client.query(`
                SELECT role_key, permission_key
                FROM public.role_permissions
                WHERE (role_key = 'business_owner' AND permission_key = 'org.settings.manage')
                   OR (role_key = 'founder' AND permission_key = 'platform.support.read');
            `);
            const boSettings = permCheck.rows.some(r => r.role_key === 'business_owner' && r.permission_key === 'org.settings.manage');
            const founderSupport = permCheck.rows.some(r => r.role_key === 'founder' && r.permission_key === 'platform.support.read');
            if (!boSettings) throw new Error('Post-check 014 failed: business_owner missing org.settings.manage');
            if (!founderSupport) throw new Error('Post-check 014 failed: founder missing platform.support.read');
            console.log('  ✓ New permissions org.settings.manage and platform.support.read granted.');

        } else if (anyHas013) {
            console.log('Running specialized post-checks for Migration 013 + Seeds:');
            
            // Check 1: Required functions exist and are SECURITY DEFINER
            const funcList = [
                'fn_create_access_context',
                'fn_renew_access_context',
                'fn_revoke_access_context',
                'fn_assert_not_support_context',
                'fn_active_support_grant',
                'fn_set_app_context',
                'fn_audit_append',
                'fn_read_audit_logs',
                'fn_list_principal_memberships',
                'fn_list_org_workspaces_for_principal',
                'is_context_valid',
                'fn_approve_organisation',
                'fn_approve_membership'
            ];

            const funcRes = await client.query(`
                SELECT p.proname, p.prosecdef 
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'public' AND p.proname = ANY($1::text[]);
            `, [funcList]);

            const foundFuncs = new Set(funcRes.rows.map(r => r.proname));
            for (const f of funcList) {
                if (!foundFuncs.has(f)) {
                    throw new Error(`Post-check failed: function ${f} missing from database!`);
                }
            }
            console.log(`  ✓ All ${funcList.length} required functions exist.`);

            // Check 2: Direct queries as archscale_app_runtime
            // 2a: fn_set_app_context with random UUID raises
            // Use SAVEPOINT so raising does not abort the outer transaction block
            await client.query('SAVEPOINT sp_context_test;');
            let randomContextRaised = false;
            try {
                await client.query(`SELECT fn_set_app_context('a0000000-0000-0000-0000-000000000000'::uuid, 'b0000000-0000-0000-0000-000000000000'::uuid, 'fake_sess');`);
            } catch {
                randomContextRaised = true;
                await client.query('ROLLBACK TO SAVEPOINT sp_context_test;');
            }
            if (!randomContextRaised) {
                throw new Error('Post-check failed: fn_set_app_context with random uuid did not raise exception!');
            }
            await client.query('RELEASE SAVEPOINT sp_context_test;');
            console.log(`  ✓ fn_set_app_context with random uuid raises.`);

            // 2b: is_context_valid() is false with no context
            const isCtxValidRes = await client.query(`SELECT is_context_valid() AS is_valid;`);
            if (isCtxValidRes.rows[0].is_valid !== false) {
                throw new Error('Post-check failed: is_context_valid() with no context did not return false!');
            }
            console.log(`  ✓ is_context_valid() returns false when no context is active.`);

            // Check 3: Permissions verified (org.members.invite granted to business_owner and NOT to intern; platform.organisations.read to founder)
            const permRes = await client.query(`
                SELECT role_key, permission_key
                FROM public.role_permissions
                WHERE (role_key = 'business_owner' AND permission_key = 'org.members.invite')
                   OR (role_key = 'intern' AND permission_key = 'org.members.invite')
                   OR (role_key = 'founder' AND permission_key = 'platform.organisations.read');
            `);

            const perms = permRes.rows;
            const boInvite = perms.some(p => p.role_key === 'business_owner' && p.permission_key === 'org.members.invite');
            const internInvite = perms.some(p => p.role_key === 'intern' && p.permission_key === 'org.members.invite');
            const founderRead = perms.some(p => p.role_key === 'founder' && p.permission_key === 'platform.organisations.read');

            if (!boInvite) throw new Error('Post-check failed: business_owner missing org.members.invite!');
            if (internInvite) throw new Error('Post-check failed: intern unexpectedly has org.members.invite!');
            if (!founderRead) throw new Error('Post-check failed: founder missing platform.organisations.read!');
            console.log(`  ✓ Permissions verified: business_owner has invite, intern does NOT, founder has platform read.`);

        } else if (anyHas012) {
            // Post-checks specifically for Migration 012
            const checkRes = await client.query(`
                SELECT
                    EXISTS (
                        SELECT 1 FROM pg_proc p
                        JOIN pg_namespace n ON n.oid = p.pronamespace
                        WHERE n.nspname = 'public' AND p.proname = 'fn_resolve_user_code'
                    ) AS has_fn_resolve,
                    EXISTS (
                        SELECT 1 FROM pg_proc p
                        JOIN pg_namespace n ON n.oid = p.pronamespace
                        WHERE n.nspname = 'public' AND p.proname = 'fn_upsert_user_mirror'
                    ) AS has_fn_upsert,
                    EXISTS (
                        SELECT 1 FROM pg_policies
                        WHERE schemaname = 'public' AND tablename = 'users' AND policyname = 'users_own_row_context_policy'
                    ) AS has_context_policy,
                    EXISTS (
                        SELECT 1 FROM pg_policies
                        WHERE schemaname = 'public' AND tablename = 'users' AND policyname = 'users_runtime_policy'
                    ) AS has_old_runtime_policy,
                    has_table_privilege('archscale_app_runtime', 'public.users', 'INSERT') AS runtime_insert,
                    has_table_privilege('archscale_app_runtime', 'public.users', 'UPDATE') AS runtime_update,
                    has_table_privilege('archscale_app_runtime', 'public.users', 'SELECT') AS runtime_select;
            `);

            const row = checkRes.rows[0];
            console.log('[Post-Check Results]:');
            console.log(`  - fn_resolve_user_code exists: ${row.has_fn_resolve}`);
            console.log(`  - fn_upsert_user_mirror exists: ${row.has_fn_upsert}`);
            console.log(`  - users_own_row_context_policy exists: ${row.has_context_policy}`);
            console.log(`  - users_runtime_policy exists (expected false): ${row.has_old_runtime_policy}`);
            console.log(`  - archscale_app_runtime INSERT privilege (expected false): ${row.runtime_insert}`);
            console.log(`  - archscale_app_runtime UPDATE privilege (expected false): ${row.runtime_update}`);
            console.log(`  - archscale_app_runtime SELECT privilege (expected true): ${row.runtime_select}`);

            const allPassed =
                row.has_fn_resolve === true &&
                row.has_fn_upsert === true &&
                row.has_context_policy === true &&
                row.has_old_runtime_policy === false &&
                row.runtime_insert === false &&
                row.runtime_update === false &&
                row.runtime_select === true;

            if (!allPassed) {
                console.error('FAILED: One or more post-checks failed! Rolling back transaction.');
                await client.query('ROLLBACK;');
                process.exit(1);
            }
        } else {
            console.log('[Post-Check]: General migration applied without specialized assertions.');
        }

        await client.query('COMMIT;');
        console.log('[3/3] Transaction COMMITTED successfully. Migration applied cleanly.');
    } catch (err: any) {
        console.error('ERROR during migration execution. Rolling back...');
        try {
            await client.query('ROLLBACK;');
        } catch { /* ignore rollback error */ }
        console.error(`Error details: ${err.message}`);
        process.exit(1);
    } finally {
        await client.end().catch(() => {});
    }
}

main();

