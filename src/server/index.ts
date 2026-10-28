import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getIdentityProvider, VerifiedPrincipal } from '../identity/index.js';
import { listPrincipalMemberships, listOrgWorkspaces } from '../context/memberships.js';
import { createAccessContext, renewAccessContext, revokeAccessContext } from '../context/access_context.js';
import { runtimePool, withAppContext } from '../db/index.js';
import { decide } from '../authz/decide.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// In-memory rate limiter: max 10 failed sign-in attempts per IP in 60s
const failedAttempts = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string): boolean {
    const now = Date.now();
    const entry = failedAttempts.get(ip);
    if (!entry || entry.resetAt <= now) {
        return true;
    }
    return entry.count < 10;
}

function recordFailedAttempt(ip: string) {
    const now = Date.now();
    const entry = failedAttempts.get(ip);
    if (!entry || entry.resetAt <= now) {
        failedAttempts.set(ip, { count: 1, resetAt: now + 60_000 });
    } else {
        entry.count++;
    }
}

export function clearRateLimit(ip: string) {
    failedAttempts.delete(ip);
}

// Fixed-floor helper for generic auth errors
async function delayToFloor(startMs: number, floorMs: number = 1000) {
    const elapsed = Date.now() - startMs;
    if (elapsed < floorMs) {
        await new Promise(resolve => setTimeout(resolve, floorMs - elapsed));
    }
}

function readBody(req: http.IncomingMessage, maxSize: number = 100 * 1024): Promise<any> {
    return new Promise((resolve, reject) => {
        let size = 0;
        let rejected = false;
        const chunks: Buffer[] = [];
        req.on('data', chunk => {
            if (rejected) return;
            size += chunk.length;
            if (size > maxSize) {
                rejected = true;
                const err = new Error('PAYLOAD_TOO_LARGE');
                (err as any).statusCode = 413;
                reject(err);
                // Pause instead of destroy so response can be sent cleanly before connection closes
                req.pause();
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            if (rejected) return;
            const raw = Buffer.concat(chunks).toString('utf-8');
            if (!raw) {
                resolve({});
                return;
            }
            try {
                resolve(JSON.parse(raw));
            } catch (err) {
                reject(new Error('INVALID_JSON'));
            }
        });
        req.on('error', err => {
            if (!rejected) reject(err);
        });
    });
}

function sendJson(res: http.ServerResponse, statusCode: number, data: any) {
    res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
    });
    res.end(JSON.stringify(data));
}

export function createServer(customIdp?: any, customRuntimePool?: any) {
    const idp = customIdp || getIdentityProvider();
    const dbPool = customRuntimePool || runtimePool;

    return http.createServer(async (req, res) => {
        const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
        const pathname = url.pathname;
        const method = req.method?.toUpperCase();
        const clientIp = req.socket.remoteAddress || '127.0.0.1';

        try {
            // Serve demo UI only if ARCHSCALE_DEMO === 'true'
            if (pathname === '/' || pathname === '/demo' || pathname === '/demo.html') {
                if (process.env.ARCHSCALE_DEMO !== 'true') {
                    res.writeHead(404, { 'Content-Type': 'text/plain' });
                    res.end('Not Found');
                    return;
                }
                const demoPath = path.join(__dirname, 'public', 'index.html');
                if (fs.existsSync(demoPath)) {
                    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                    fs.createReadStream(demoPath).pipe(res);
                    return;
                } else {
                    res.writeHead(404, { 'Content-Type': 'text/plain' });
                    res.end('Demo page not found');
                    return;
                }
            }

            // POST /api/session/sign-in
            if (pathname === '/api/session/sign-in' && method === 'POST') {
                const start = Date.now();
                if (!checkRateLimit(clientIp)) {
                    await delayToFloor(start, 1000);
                    return sendJson(res, 429, { error: 'AUTH_RATE_LIMIT_EXCEEDED' });
                }

                let body: any;
                try {
                    body = await readBody(req);
                } catch (err: any) {
                    if (err.statusCode === 413) {
                        return sendJson(res, 413, { error: 'PAYLOAD_TOO_LARGE' });
                    }
                    return sendJson(res, 400, { error: 'INVALID_REQUEST' });
                }

                try {
                    const session = await idp.signIn({
                        email: body.email,
                        userCode: body.userCode,
                        password: body.password
                    });
                    clearRateLimit(clientIp);

                    // Check if user has verified MFA factors
                    let mfaRequired = false;
                    try {
                        const mfaStatus = await idp.getMfaStatus(session.principal.id);
                        mfaRequired = mfaStatus.factors.some(f => f.status === 'verified') && session.principal.aal !== 'aal2';
                    } catch {
                        mfaRequired = false;
                    }

                    return sendJson(res, 200, {
                        accessToken: session.accessToken,
                        refreshToken: session.refreshToken,
                        principal: session.principal,
                        mfaRequired
                    });
                } catch (err) {
                    recordFailedAttempt(clientIp);
                    await delayToFloor(start, 1000);
                    return sendJson(res, 401, { error: 'AUTH_SIGNIN_FAILED' });
                }
            }

            // Extract Bearer token for authenticated endpoints
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

            if (!token) {
                return sendJson(res, 401, { error: 'AUTH_TOKEN_MISSING' });
            }

            let principal: VerifiedPrincipal;
            try {
                principal = await idp.verify(token);
            } catch {
                return sendJson(res, 401, { error: 'AUTH_TOKEN_INVALID' });
            }

            // POST /api/session/mfa/verify
            if (pathname === '/api/session/mfa/verify' && method === 'POST') {
                const start = Date.now();
                if (!checkRateLimit(clientIp)) {
                    await delayToFloor(start, 1000);
                    return sendJson(res, 429, { error: 'AUTH_RATE_LIMIT_EXCEEDED' });
                }

                let body: any;
                try {
                    body = await readBody(req);
                } catch (err: any) {
                    if (err.statusCode === 413) {
                        return sendJson(res, 413, { error: 'PAYLOAD_TOO_LARGE' });
                    }
                    return sendJson(res, 400, { error: 'INVALID_REQUEST' });
                }

                const code = body?.code;
                if (!code || typeof code !== 'string') {
                    recordFailedAttempt(clientIp);
                    await delayToFloor(start, 1000);
                    return sendJson(res, 401, { error: 'AUTH_MFA_FAILED' });
                }

                try {
                    const mfaStatus = await idp.getMfaStatus(principal.id);
                    const verifiedFactor = mfaStatus.factors.find(f => f.status === 'verified');
                    if (!verifiedFactor) {
                        recordFailedAttempt(clientIp);
                        await delayToFloor(start, 1000);
                        return sendJson(res, 401, { error: 'AUTH_MFA_FAILED' });
                    }

                    const challenge = await idp.challengeMfa(verifiedFactor.id);
                    const verification = await (idp as any).verifyMfa(
                        verifiedFactor.id,
                        challenge.id,
                        code,
                        principal.sessionId,
                        principal.id,
                        principal.email
                    );

                    clearRateLimit(clientIp);
                    return sendJson(res, 200, {
                        accessToken: verification.accessToken,
                        refreshToken: verification.refreshToken,
                        aal: verification.aal
                    });
                } catch {
                    recordFailedAttempt(clientIp);
                    await delayToFloor(start, 1000);
                    return sendJson(res, 401, { error: 'AUTH_MFA_FAILED' });
                }
            }

            // GET /api/session/memberships
            if (pathname === '/api/session/memberships' && method === 'GET') {
                const memberships = await listPrincipalMemberships(principal.id, dbPool);
                return sendJson(res, 200, { memberships });
            }

            // GET /api/session/workspaces?organisationId=...
            if (pathname === '/api/session/workspaces' && method === 'GET') {
                const orgId = url.searchParams.get('organisationId');
                if (!orgId) {
                    return sendJson(res, 400, { error: 'MISSING_ORG_ID' });
                }
                const workspaces = await listOrgWorkspaces(principal.id, orgId, dbPool);
                return sendJson(res, 200, { workspaces });
            }

            // POST /api/session/context
            if (pathname === '/api/session/context' && method === 'POST') {
                let body: any;
                try {
                    body = await readBody(req);
                } catch (err: any) {
                    if (err.statusCode === 413) {
                        return sendJson(res, 413, { error: 'PAYLOAD_TOO_LARGE' });
                    }
                    return sendJson(res, 400, { error: 'INVALID_REQUEST' });
                }
                try {
                    const context = await createAccessContext({
                        userId: principal.id,
                        sessionId: principal.sessionId,
                        organisationId: body.organisationId,
                        workspaceId: body.workspaceId,
                        aal: principal.aal === 'aal2' ? 'aal2' : 'aal1',
                        supportGrantId: body.supportGrantId
                    }, dbPool);
                    return sendJson(res, 200, { context });
                } catch (err: any) {
                    return sendJson(res, 400, { error: err.message || 'AUTH_CONTEXT_CREATE_FAILED' });
                }
            }

            // POST /api/session/context/renew
            if (pathname === '/api/session/context/renew' && method === 'POST') {
                const body = await readBody(req);
                const contextId = body.contextId || req.headers['x-archscale-context'];
                if (!contextId || typeof contextId !== 'string') {
                    return sendJson(res, 400, { error: 'AUTH_CONTEXT_REQUIRED' });
                }
                try {
                    const context = await renewAccessContext(contextId, principal.id, principal.sessionId, dbPool);
                    return sendJson(res, 200, { context });
                } catch (err: any) {
                    return sendJson(res, 400, { error: err.message || 'AUTH_CONTEXT_RENEW_FAILED' });
                }
            }

            // POST /api/session/logout
            if (pathname === '/api/session/logout' && method === 'POST') {
                let body: any = {};
                try {
                    body = await readBody(req);
                } catch {}
                const contextId = body.contextId || req.headers['x-archscale-context'];
                if (contextId && typeof contextId === 'string') {
                    await revokeAccessContext(contextId, principal.id, principal.sessionId).catch(() => {});
                }
                if (principal.sessionId) {
                    await idp.revokeSession(principal.sessionId).catch(() => {});
                }
                return sendJson(res, 200, { success: true });
            }

            // All remaining endpoints require X-ArchScale-Context
            const contextId = req.headers['x-archscale-context'] as string;
            if (!contextId) {
                return sendJson(res, 401, { error: 'AUTH_CONTEXT_REQUIRED' });
            }

            // Execute within database context
            const client = await dbPool.connect();
            try {
                await client.query('BEGIN;');
                try {
                    await client.query('SELECT fn_set_app_context($1::uuid, $2::uuid, $3::text);', [
                        contextId,
                        principal.id,
                        principal.sessionId
                    ]);
                } catch (ctxErr: any) {
                    console.error('fn_set_app_context failed:', ctxErr.message);
                    await client.query('ROLLBACK;').catch(() => {});
                    return sendJson(res, 403, { error: 'AUTH_CONTEXT_INVALID' });
                }

                // GET /api/me
                if (pathname === '/api/me' && method === 'GET') {
                    // /api/me requires only a valid context, no specific route permission
                    const ctxQuery = await client.query(`
                        SELECT 
                            ac.id AS context_id,
                            ac.user_id,
                            ac.organisation_id,
                            o.name AS organisation_name,
                            o.portal,
                            o.tenant_type_key,
                            ac.workspace_id,
                            w.name AS workspace_name,
                            m.role_key,
                            ac.aal_level AS aal,
                            ac.expires_at
                        FROM public.access_contexts ac
                        JOIN public.organisations o ON o.id = ac.organisation_id
                        JOIN public.workspaces w ON w.id = ac.workspace_id
                        JOIN public.memberships m ON m.id = ac.membership_id
                        WHERE ac.id = $1::uuid;
                    `, [contextId]);
                    const ctxRow = ctxQuery.rows[0];
                    if (!ctxRow) {
                        return sendJson(res, 403, { error: 'AUTH_CONTEXT_INVALID' });
                    }
                    return sendJson(res, 200, {
                        principal: {
                            id: principal.id,
                            email: principal.email,
                            aal: principal.aal
                        },
                        context: {
                            contextId: ctxRow.context_id,
                            organisationId: ctxRow.organisation_id,
                            organisationName: ctxRow.organisation_name,
                            workspaceId: ctxRow.workspace_id,
                            workspaceName: ctxRow.workspace_name,
                            roleKey: ctxRow.role_key,
                            portal: ctxRow.portal,
                            tenantTypeKey: ctxRow.tenant_type_key,
                            expiresAt: ctxRow.expires_at
                        }
                    });
                }

                // Protected Sample 1: GET /api/platform/organisations
                if (pathname === '/api/platform/organisations' && method === 'GET') {
                    const decision = await decide(client, principal, contextId, 'platform.organisations.read');
                    if (!decision.allow) {
                        return sendJson(res, 403, { error: decision.reasonCode, decision });
                    }
                    // RLS active for platform organisation reads
                    const orgs = await client.query(`SELECT id, name, portal, status FROM public.organisations ORDER BY name;`);
                    return sendJson(res, 200, { decision, data: orgs.rows });
                }

                // Protected Sample 2: GET /api/org/members
                if (pathname === '/api/org/members' && method === 'GET') {
                    const decision = await decide(client, principal, contextId, 'org.members.read');
                    if (!decision.allow) {
                        return sendJson(res, 403, { error: decision.reasonCode, decision });
                    }
                    // Read members of current context organisation
                    const members = await client.query(
                        `SELECT m.id, m.user_id, m.role_key, m.status 
                         FROM public.memberships m 
                         WHERE m.organisation_id = $1::uuid;`,
                        [decision.organisationId]
                    );
                    return sendJson(res, 200, { decision, data: members.rows });
                }

                // Protected Sample 3: POST /api/org/invitations
                if (pathname === '/api/org/invitations' && method === 'POST') {
                    let body: any = {};
                    try {
                        body = await readBody(req);
                    } catch {}
                    const decision = await decide(client, principal, contextId, 'org.members.invite', { isMutation: true });
                    if (!decision.allow) {
                        return sendJson(res, 403, { error: decision.reasonCode, decision });
                    }
                    return sendJson(res, 200, {
                        decision,
                        invited: {
                            email: body.email,
                            roleKey: body.roleKey || 'member',
                            organisationId: decision.organisationId
                        }
                    });
                }

                return sendJson(res, 404, { error: 'NOT_FOUND' });
            } finally {
                await client.query('COMMIT;').catch(() => {});
                client.release();
            }
        } catch (err: any) {
            return sendJson(res, 500, { error: 'INTERNAL_SERVER_ERROR', message: err.message });
        }
    });
}

// Auto-start server when run directly as CLI entrypoint
const isMain = process.argv[1] && (
    process.argv[1].endsWith('src/server/index.ts') ||
    process.argv[1].endsWith('src\\server\\index.ts') ||
    process.argv[1].endsWith('server.ts')
);

if (isMain) {
    const port = parseInt(process.env.PORT || '3000', 10);
    const host = '127.0.0.1';
    const server = createServer();
    server.listen(port, host, () => {
        console.log(`[ArchScale Server] Listening on http://${host}:${port} (Demo mode: ${process.env.ARCHSCALE_DEMO === 'true'})`);
    });
}
