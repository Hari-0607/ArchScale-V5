import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';
import { exec } from 'child_process';

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const pool = new Pool({
    host: '127.0.0.1',
    port: 5433,
    user: 'postgres',
    password: '',
    database: 'archscale_phase1_clean'
});

const PORT = 3000;

const server = http.createServer(async (req, res) => {
    // Enable CORS & JSON headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const parsedUrl = new URL(req.url, `http://localhost:${PORT}`);
    const pathname = parsedUrl.pathname;

    // Static files
    if (pathname === '/' || pathname === '/index.html') {
        const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf-8');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(html);
        return;
    }

    // API: Status
    if (pathname === '/api/status' && req.method === 'GET') {
        try {
            const version = await pool.query('SELECT version();');
            const orgs = await pool.query('SELECT count(*)::int as count FROM organisations;');
            const members = await pool.query('SELECT count(*)::int as count FROM memberships;');
            const seats = await pool.query('SELECT sum(allocated_seats)::int as allocated, sum(seat_limit)::int as total FROM organisation_seats;');
            const audit = await pool.query('SELECT count(*)::int as count FROM audit_logs;');
            const rolesCount = await pool.query('SELECT count(*)::int as count FROM roles;');
            const permsCount = await pool.query('SELECT count(*)::int as count FROM permissions;');

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                status: 'CONNECTED',
                postgresVersion: version.rows[0].version,
                counts: {
                    organisations: orgs.rows[0].count,
                    memberships: members.rows[0].count,
                    seatsAllocated: seats.rows[0].allocated || 0,
                    seatsTotal: seats.rows[0].total || 0,
                    auditLogs: audit.rows[0].count,
                    roles: rolesCount.rows[0].count,
                    permissions: permsCount.rows[0].count
                }
            }));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'ERROR', error: err.message }));
        }
        return;
    }

    // API: Roles
    if (pathname === '/api/roles' && req.method === 'GET') {
        try {
            const data = await pool.query(`
                SELECT r.key, r.name, r.description, r.portal, r.level, r.min_aal, 
                       r.expiry_required, r.max_duration, r.requires_approval,
                       COUNT(rp.permission_key)::int as permission_count
                FROM roles r
                LEFT JOIN role_permissions rp ON rp.role_key = r.key
                GROUP BY r.key, r.name, r.description, r.portal, r.level, r.min_aal, r.expiry_required, r.max_duration, r.requires_approval
                ORDER BY r.level DESC, r.portal ASC;
            `);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(data.rows));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
    }

    // API: Permissions
    if (pathname === '/api/permissions' && req.method === 'GET') {
        try {
            const data = await pool.query(`
                SELECT key, name, description, min_aal,
                       split_part(key, '.', 1) as module
                FROM permissions
                ORDER BY split_part(key, '.', 1), key;
            `);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(data.rows));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
    }

    // API: Role-Permissions Matrix
    if (pathname === '/api/role-permissions' && req.method === 'GET') {
        try {
            const data = await pool.query(`
                SELECT role_key, permission_key
                FROM role_permissions;
            `);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(data.rows));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
    }

    // API: Organisations
    if (pathname === '/api/organisations' && req.method === 'GET') {
        try {
            const data = await pool.query(`
                SELECT o.id, o.name, o.portal, o.tenant_type_key, o.status, o.created_at,
                       COUNT(DISTINCT m.id)::int as member_count,
                       COUNT(DISTINCT w.id)::int as workspace_count
                FROM organisations o
                LEFT JOIN memberships m ON m.organisation_id = o.id
                LEFT JOIN workspaces w ON w.organisation_id = o.id
                GROUP BY o.id, o.name, o.portal, o.tenant_type_key, o.status, o.created_at
                ORDER BY o.portal DESC, o.created_at ASC;
            `);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(data.rows));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
    }

    // API: Memberships
    if (pathname === '/api/memberships' && req.method === 'GET') {
        try {
            const data = await pool.query(`
                SELECT m.id, u.id as user_id, u.user_code, u.email, o.id as org_id, o.name as org_name, 
                       o.portal as org_portal, o.status as org_status,
                       m.role_key, r.name as role_name, r.level, r.min_aal, 
                       m.status, m.expires_at, m.is_primary_owner
                FROM memberships m
                JOIN users u ON u.id = m.user_id
                JOIN organisations o ON o.id = m.organisation_id
                JOIN roles r ON r.key = m.role_key
                ORDER BY r.level DESC, m.created_at ASC;
            `);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(data.rows));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
    }

    // API: Workspaces
    if (pathname === '/api/workspaces' && req.method === 'GET') {
        try {
            const data = await pool.query(`
                SELECT w.id, w.name, w.is_default, w.is_active, o.name as org_name, o.id as org_id
                FROM workspaces w
                JOIN organisations o ON o.id = w.organisation_id
                ORDER BY o.name, w.is_default DESC, w.name;
            `);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(data.rows));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
    }

    // API: Seats
    if (pathname === '/api/seats' && req.method === 'GET') {
        try {
            const data = await pool.query(`
                SELECT os.id, o.name as org_name, os.app_key, ac.name as app_name, 
                       os.role_key, r.name as role_name, os.seat_limit, os.allocated_seats
                FROM organisation_seats os
                JOIN organisations o ON o.id = os.organisation_id
                LEFT JOIN app_catalogue ac ON ac.app_key = os.app_key
                LEFT JOIN roles r ON r.key = os.role_key
                ORDER BY o.name, ac.name, os.role_key;
            `);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(data.rows));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
    }

    // API: Access Contexts (Active Sessions)
    if (pathname === '/api/contexts' && req.method === 'GET') {
        try {
            const data = await pool.query(`
                SELECT c.id, c.session_id, u.user_code, u.email, o.name as org_name, 
                       w.name as workspace_name, r.name as role_name, r.level,
                       c.expires_at, is_context_valid(c.id) as is_valid
                FROM access_contexts c
                JOIN users u ON u.id = c.user_id
                JOIN organisations o ON o.id = c.organisation_id
                JOIN workspaces w ON w.id = c.workspace_id
                JOIN memberships m ON m.id = c.membership_id
                JOIN roles r ON r.key = m.role_key
                ORDER BY c.created_at DESC;
            `);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(data.rows));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
    }

    // API: Evaluate Policy Decision (Live Interactive Authorisation Sandbox)
    if (pathname === '/api/evaluate-policy' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { userId, organisationId, workspaceId, permissionKey } = JSON.parse(body || '{}');

                if (!userId || !organisationId || !permissionKey) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'userId, organisationId, and permissionKey are required' }));
                    return;
                }

                // 1. Fetch user & membership
                const memRes = await pool.query(`
                    SELECT m.id as membership_id, m.status as membership_status, m.expires_at as membership_expires_at,
                           u.user_code, u.email, 
                           o.id as org_id, o.name as org_name, o.portal as org_portal, o.status as org_status, o.tenant_type_key,
                           r.key as role_key, r.name as role_name, r.level as role_level, r.min_aal as role_min_aal
                    FROM users u
                    LEFT JOIN memberships m ON m.user_id = u.id AND m.organisation_id = $2
                    LEFT JOIN organisations o ON o.id = $2
                    LEFT JOIN roles r ON r.key = m.role_key
                    WHERE u.id = $1;
                `, [userId, organisationId]);

                if (memRes.rows.length === 0) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'User or Organisation not found' }));
                    return;
                }

                const rec = memRes.rows[0];

                // 2. Fetch permission
                const permRes = await pool.query(`
                    SELECT key, name, description, min_aal FROM permissions WHERE key = $1;
                `, [permissionKey]);

                if (permRes.rows.length === 0) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: `Permission '${permissionKey}' is not registered` }));
                    return;
                }

                const perm = permRes.rows[0];

                // 3. Check role permission grant
                const roleHasPermRes = await pool.query(`
                    SELECT 1 FROM role_permissions WHERE role_key = $1 AND permission_key = $2;
                `, [rec.role_key, permissionKey]);

                const hasPermission = roleHasPermRes.rows.length > 0;

                // 4. Evaluate checks
                const checks = [];
                let allowed = true;
                let failureReason = null;

                // Check 1: User has membership in target org
                if (!rec.membership_id) {
                    checks.push({ name: 'Organisation Membership Binding', pass: false, detail: `User is NOT a member of ${rec.org_name || 'the organisation'}.` });
                    allowed = false;
                    failureReason = failureReason || 'User has no membership binding in target organisation';
                } else {
                    checks.push({ name: 'Organisation Membership Binding', pass: true, detail: `Bound to ${rec.org_name} under role ${rec.role_name}` });
                }

                // Check 2: Organisation status ACTIVE
                if (rec.org_status !== 'ACTIVE') {
                    checks.push({ name: 'Organisation Lifecycle Status', pass: false, detail: `Organisation status is '${rec.org_status}' (must be ACTIVE).` });
                    allowed = false;
                    failureReason = failureReason || `Organisation is ${rec.org_status}`;
                } else {
                    checks.push({ name: 'Organisation Lifecycle Status', pass: true, detail: 'Organisation status is ACTIVE' });
                }

                // Check 3: Membership status ACTIVE
                if (rec.membership_status !== 'ACTIVE') {
                    checks.push({ name: 'Membership Status', pass: false, detail: `Membership status is '${rec.membership_status}' (must be ACTIVE).` });
                    allowed = false;
                    failureReason = failureReason || `Membership is ${rec.membership_status}`;
                } else {
                    checks.push({ name: 'Membership Status', pass: true, detail: 'Membership is ACTIVE' });
                }

                // Check 4: Membership expiration
                if (rec.membership_expires_at && new Date(rec.membership_expires_at) < new Date()) {
                    checks.push({ name: 'Account Expiry Window', pass: false, detail: `Membership expired on ${new Date(rec.membership_expires_at).toISOString()}` });
                    allowed = false;
                    failureReason = failureReason || 'Membership has expired';
                } else if (rec.membership_expires_at) {
                    checks.push({ name: 'Account Expiry Window', pass: true, detail: `Valid (expires ${new Date(rec.membership_expires_at).toLocaleDateString()})` });
                } else {
                    checks.push({ name: 'Account Expiry Window', pass: true, detail: 'No expiration limit required' });
                }

                // Check 5: Role Permission Grant
                if (!hasPermission) {
                    checks.push({ name: 'RBAC Permission Capability', pass: false, detail: `Role '${rec.role_name}' does not grant permission '${permissionKey}'.` });
                    allowed = false;
                    failureReason = failureReason || `Role '${rec.role_name}' lacks '${permissionKey}'`;
                } else {
                    checks.push({ name: 'RBAC Permission Capability', pass: true, detail: `Role '${rec.role_name}' (Level ${rec.role_level}) holds '${permissionKey}'` });
                }

                // Check 6: Portal segregation
                if (perm.key.startsWith('platform.') && rec.org_portal !== 'platform') {
                    checks.push({ name: 'Portal Realm Segregation', pass: false, detail: `Platform permissions cannot be executed from subscriber portals.` });
                    allowed = false;
                    failureReason = failureReason || 'Cannot execute platform permissions from subscriber portal';
                } else {
                    checks.push({ name: 'Portal Realm Segregation', pass: true, detail: `Operation permissible in ${rec.org_portal} portal` });
                }

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    decision: allowed ? 'ALLOW' : 'DENY',
                    summary: allowed 
                        ? `AUTHORISED: ${rec.email} (${rec.role_name}) is granted '${perm.name}' in ${rec.org_name}.`
                        : `DENIED: Access blocked due to: ${failureReason}.`,
                    actor: {
                        userCode: rec.user_code,
                        email: rec.email,
                        role: rec.role_name,
                        roleKey: rec.role_key,
                        level: rec.role_level,
                        orgName: rec.org_name,
                        portal: rec.org_portal
                    },
                    permission: {
                        key: perm.key,
                        name: perm.name,
                        description: perm.description,
                        minAal: perm.min_aal
                    },
                    ruleChecks: checks,
                    timestamp: new Date().toISOString()
                }));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    // API: Audit Logs
    if (pathname === '/api/audit' && req.method === 'GET') {
        try {
            const data = await pool.query(`
                SELECT a.id, a.action, a.target_entity, a.target_id, a.diff, a.created_at,
                       u.user_code as actor_code, u.email as actor_email, o.name as org_name
                FROM audit_logs a
                LEFT JOIN users u ON u.id = a.actor_user_id
                LEFT JOIN organisations o ON o.id = a.organisation_id
                ORDER BY a.created_at DESC
                LIMIT 30;
            `);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(data.rows));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
    }

    // API: Trigger Attack Invariant Test
    if (pathname === '/api/attack' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { attackType } = JSON.parse(body || '{}');
                let sql = '';
                let description = '';

                switch (attackType) {
                    case 'duplicate_platform_org':
                        description = 'Attempting to create a second platform organisation';
                        sql = "INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Rogue Platform Org', 'platform', NULL, 'ACTIVE');";
                        break;
                    case 'audit_update':
                        description = 'Attempting to UPDATE immutable audit log';
                        sql = "UPDATE audit_logs SET action = 'hacked' WHERE id IN (SELECT id FROM audit_logs LIMIT 1);";
                        break;
                    case 'audit_delete':
                        description = 'Attempting to DELETE from immutable audit log';
                        sql = "DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs LIMIT 1);";
                        break;
                    case 'audit_truncate':
                        description = 'Attempting to TRUNCATE immutable audit log';
                        sql = "TRUNCATE TABLE audit_logs;";
                        break;
                    case 'active_member_nonactive_org':
                        description = 'Attempting to activate membership under APPLIED organisation';
                        sql = `
                            DO $$
                            DECLARE v_uid UUID; v_oid UUID;
                            BEGIN
                                INSERT INTO users (user_code, email) VALUES ('ATTACK-USER', 'attack@test.com') RETURNING id INTO v_uid;
                                INSERT INTO organisations (name, portal, tenant_type_key, status) VALUES ('Unapproved Org', 'subscriber', 'studio_owner', 'APPLIED') RETURNING id INTO v_oid;
                                INSERT INTO memberships (user_id, organisation_id, role_key, status) VALUES (v_uid, v_oid, 'business_owner', 'ACTIVE');
                            END $$;
                        `;
                        break;
                    case 'intern_no_expiry':
                        description = 'Attempting to create intern membership without required expires_at';
                        sql = `
                            DO $$
                            DECLARE v_uid UUID; v_oid UUID;
                            BEGIN
                                SELECT id INTO v_oid FROM organisations WHERE portal = 'subscriber' AND status = 'ACTIVE' LIMIT 1;
                                INSERT INTO users (user_code, email) VALUES ('ATTACK-INT', 'intern.no.exp@test.com') RETURNING id INTO v_uid;
                                INSERT INTO memberships (user_id, organisation_id, role_key, status, expires_at) VALUES (v_uid, v_oid, 'intern', 'PENDING_APPROVAL', NULL);
                            END $$;
                        `;
                        break;
                    case 'delete_last_founder':
                        description = 'Attempting to delete the only active founder of the platform organisation';
                        sql = "DELETE FROM memberships WHERE role_key = 'founder' AND organisation_id = '00000000-0000-0000-0000-000000000001';";
                        break;
                    case 'both_targets_share_grant':
                        description = 'Attempting share grant with both target_org_id and target_user_id set';
                        sql = `
                            DO $$
                            DECLARE v_oid UUID; v_uid UUID; v_gid UUID;
                            BEGIN
                                SELECT id INTO v_oid FROM organisations WHERE portal = 'subscriber' LIMIT 1;
                                SELECT id INTO v_uid FROM users LIMIT 1;
                                SELECT id INTO v_gid FROM memberships LIMIT 1;
                                INSERT INTO share_grants (source_organisation_id, target_org_id, target_user_id, resource_type, resource_id, granted_by, expires_at)
                                VALUES (v_oid, v_oid, v_uid, 'project', 'P1', v_gid, now() + interval '1 day');
                            END $$;
                        `;
                        break;
                    default:
                        throw new Error('Unknown attack scenario');
                }

                try {
                    await pool.query(sql);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        outcome: 'FAILED_TO_DEFEND',
                        message: 'VULNERABILITY DETECTED: The database allowed this illegal action!',
                        description
                    }));
                } catch (pgError) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        outcome: 'REJECTED_BY_POSTGRES',
                        description,
                        blocked: true,
                        errorCode: pgError.code || 'EXCEPTION',
                        errorMessage: pgError.message,
                        detail: pgError.detail || pgError.hint || 'Denied by database engine invariant.'
                    }));
                }
            } catch (err) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }

    // API: Run Vitest Suite
    if (pathname === '/api/run-tests' && req.method === 'POST') {
        exec('npx vitest run', (err, stdout, stderr) => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: !err,
                output: stdout + (stderr ? '\n' + stderr : '')
            }));
        });
        return;
    }

    res.writeHead(404);
    res.end('Not Found');
});

server.listen(PORT, () => {
    console.log(`\n======================================================`);
    console.log(`ArchScale V05 Phase 1 Visual Testbench Live`);
    console.log(`URL: http://localhost:${PORT}`);
    console.log(`Database: 127.0.0.1:5433/archscale_phase1_clean`);
    console.log(`======================================================\n`);
});
