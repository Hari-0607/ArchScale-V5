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

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                status: 'CONNECTED',
                postgresVersion: version.rows[0].version,
                counts: {
                    organisations: orgs.rows[0].count,
                    memberships: members.rows[0].count,
                    seatsAllocated: seats.rows[0].allocated || 0,
                    seatsTotal: seats.rows[0].total || 0,
                    auditLogs: audit.rows[0].count
                }
            }));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'ERROR', error: err.message }));
        }
        return;
    }

    // API: Organisations
    if (pathname === '/api/organisations' && req.method === 'GET') {
        try {
            const data = await pool.query(`
                SELECT o.id, o.name, o.portal, o.tenant_type_key, o.status, o.created_at,
                       COUNT(m.id)::int as member_count
                FROM organisations o
                LEFT JOIN memberships m ON m.organisation_id = o.id
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
                SELECT m.id, u.user_code, u.email, o.name as org_name, m.role_key, r.level, m.status, m.expires_at, m.is_primary_owner
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

    // API: Seats
    if (pathname === '/api/seats' && req.method === 'GET') {
        try {
            const data = await pool.query(`
                SELECT os.id, o.name as org_name, os.app_key, os.role_key, os.seat_limit, os.allocated_seats
                FROM organisation_seats os
                JOIN organisations o ON o.id = os.organisation_id
                ORDER BY o.name, os.role_key;
            `);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(data.rows));
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
    }

    // API: Audit Logs
    if (pathname === '/api/audit' && req.method === 'GET') {
        try {
            const data = await pool.query(`
                SELECT id, action, target_entity, target_id, diff, created_at
                FROM audit_logs
                ORDER BY created_at DESC
                LIMIT 20;
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
                    // If it did NOT fail, that's a security flaw!
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        outcome: 'FAILED_TO_DEFEND',
                        message: 'VULNERABILITY DETECTED: The database allowed this illegal action!',
                        description
                    }));
                } catch (pgError) {
                    // EXPECTED: PostgreSQL rejected it!
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
