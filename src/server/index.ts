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

function clearRateLimit(ip: string) {
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
        const chunks: Buffer[] = [];
        req.on('data', chunk => {
            size += chunk.length;
            if (size > maxSize) {
                reject(new Error('PAYLOAD_TOO_LARGE'));
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
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
        req.on('error', reject);
    });
}

function sendJson(res: http.ServerResponse, statusCode: number, data: any) {
    res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
    });
    res.end(JSON.stringify(data));
}

export function createServer() {
    const idp = getIdentityProvider();

    return http.createServer(async (req, res) => {
        const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
        const pathname = url.pathname;
        const method = req.method?.toUpperCase();
        const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

        try {
            // Serve demo UI
            if (pathname === '/' || pathname === '/demo' || pathname === '/demo.html') {
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
                } catch {
                    return sendJson(res, 400, { error: 'INVALID_REQUEST' });
                }

                try {
                    const session = await idp.signIn({
                        email: body.email,
                        userCode: body.userCode,
                        password: body.password
                    });
                    clearRateLimit(clientIp);
                    return sendJson(res, 200, {
                        accessToken: session.accessToken,
                        refreshToken: session.refreshToken,
                        principal: session.principal
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

            // GET /api/session/memberships
            if (pathname === '/api/session/memberships' && method === 'GET') {
                const memberships = await listPrincipalMemberships(principal.id);
                return sendJson(res, 200, { memberships });
            }

            // GET /api/session/workspaces?organisationId=...
            if (pathname === '/api/session/workspaces' && method === 'GET') {
                const orgId = url.searchParams.get('organisationId');
                if (!orgId) {
                    return sendJson(res, 400, { error: 'MISSING_ORG_ID' });
                }
                const workspaces = await listOrgWorkspaces(principal.id, orgId);
                return sendJson(res, 200, { workspaces });
            }

            // POST /api/session/context
            if (pathname === '/api/session/context' && method === 'POST') {
                const body = await readBody(req);
                try {
                    const context = await createAccessContext({
                        userId: principal.id,
                        sessionId: principal.sessionId,
                        organisationId: body.organisationId,
                        workspaceId: body.workspaceId,
                        aal: principal.aal === 'aal2' ? 'aal2' : 'aal1',
                        supportGrantId: body.supportGrantId
                    });
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
                    const context = await renewAccessContext(contextId, principal.id, principal.sessionId);
                    return sendJson(res, 200, { context });
                } catch (err: any) {
                    return sendJson(res, 400, { error: err.message || 'AUTH_CONTEXT_RENEW_FAILED' });
                }
            }

            // POST /api/session/logout
            if (pathname === '/api/session/logout' && method === 'POST') {
                const body = await readBody(req);
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

            // Execute within database context using withAppContext
            return await withAppContext(contextId, principal.id, principal.sessionId, async client => {
                // GET /api/me
                if (pathname === '/api/me' && method === 'GET') {
                    const decision = await decide(client, principal, contextId, 'org.members.read');
                    if (!decision.allow) {
                        return sendJson(res, 403, { decision });
                    }
                    return sendJson(res, 200, {
                        principal: {
                            id: principal.id,
                            email: principal.email,
                            aal: principal.aal
                        },
                        context: {
                            contextId: decision.contextId,
                            organisationId: decision.organisationId,
                            organisationName: decision.organisationName,
                            workspaceId: decision.workspaceId,
                            workspaceName: decision.workspaceName,
                            roleKey: decision.roleKey,
                            portal: decision.portal,
                            tenantTypeKey: decision.tenantTypeKey,
                            expiresAt: decision.expiresAt
                        }
                    });
                }

                // Protected Sample 1: GET /api/platform/organisations
                if (pathname === '/api/platform/organisations' && method === 'GET') {
                    const decision = await decide(client, principal, contextId, 'platform.organisations.read');
                    if (!decision.allow) {
                        return sendJson(res, 403, { decision });
                    }
                    // RLS active for platform organisation reads
                    const orgs = await client.query(`SELECT id, name, portal, status FROM public.organisations ORDER BY name;`);
                    return sendJson(res, 200, { decision, data: orgs.rows });
                }

                // Protected Sample 2: GET /api/org/members
                if (pathname === '/api/org/members' && method === 'GET') {
                    const decision = await decide(client, principal, contextId, 'org.members.read');
                    if (!decision.allow) {
                        return sendJson(res, 403, { decision });
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
                    const body = await readBody(req);
                    const decision = await decide(client, principal, contextId, 'org.members.invite', { isMutation: true });
                    if (!decision.allow) {
                        return sendJson(res, 403, { decision });
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
            });
        } catch (err: any) {
            return sendJson(res, 500, { error: 'INTERNAL_SERVER_ERROR', message: err.message });
        }
    });
}
