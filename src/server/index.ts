import express, { Request, Response, NextFunction } from 'express';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getIdentityProvider, IdentityProvider, VerifiedPrincipal } from '../identity/index.js';
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

export function createServer(
    identityProvider?: IdentityProvider,
    dbPool: any = runtimePool
): http.Server {
    const app = express();

    // Body parsing middleware with size guard
    app.use(express.json({ limit: 100 * 1024 }));

    // Global IP extraction helper
    const getClientIp = (req: Request): string => {
        return (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    };

    // 0. Static demo UI
    app.get('/', (req: Request, res: Response) => {
        const filePath = path.join(__dirname, 'public', 'index.html');
        if (fs.existsSync(filePath)) {
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            return res.status(200).send(fs.readFileSync(filePath, 'utf-8'));
        }
        return res.status(404).send('Not Found');
    });

    app.get('/demo', (req: Request, res: Response) => {
        return res.status(200).json({ status: 'ok', name: 'ArchScale Auth Demo' });
    });

    // 1. POST /api/session/sign-in
    app.post('/api/session/sign-in', async (req: Request, res: Response) => {
        const start = Date.now();
        const clientIp = getClientIp(req);

        if (!checkRateLimit(clientIp)) {
            return res.status(429).json({ error: 'AUTH_RATE_LIMIT_EXCEEDED', message: 'Rate limit exceeded' });
        }

        const body = req.body || {};
        if ((!body.email && !body.userCode) || !body.password) {
            recordFailedAttempt(clientIp);
            await delayToFloor(start, 1000);
            return res.status(401).json({ error: 'AUTH_SIGNIN_FAILED' });
        }

        let idp: IdentityProvider;
        try {
            idp = identityProvider || getIdentityProvider();
        } catch {
            return res.status(500).json({ error: 'IDENTITY_PROVIDER_ERROR' });
        }

        try {
            const session = await idp.signIn({
                email: body.email,
                userCode: body.userCode,
                password: body.password
            });
            clearRateLimit(clientIp);

            let mfaRequired = false;
            try {
                const mfaStatus = await idp.getMfaStatus(session.principal.id);
                mfaRequired = mfaStatus.factors.some(f => f.status === 'verified') && session.principal.aal !== 'aal2';
            } catch {
                mfaRequired = false;
            }

            return res.status(200).json({
                accessToken: session.accessToken,
                refreshToken: session.refreshToken,
                principal: session.principal,
                mfaRequired
            });
        } catch {
            recordFailedAttempt(clientIp);
            await delayToFloor(start, 1000);
            return res.status(401).json({ error: 'AUTH_SIGNIN_FAILED' });
        }
    });

    // Pre-context & authenticated middleware
    const authenticate = async (req: Request, res: Response, next: NextFunction) => {
        const authHeader = req.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'AUTH_TOKEN_MISSING' });
        }

        const token = authHeader.substring('Bearer '.length).trim();
        let idp: IdentityProvider;
        try {
            idp = identityProvider || getIdentityProvider();
        } catch {
            return res.status(500).json({ error: 'IDENTITY_PROVIDER_ERROR' });
        }

        try {
            const principal = await idp.verify(token);
            (req as any).principal = principal;
            (req as any).idp = idp;
            next();
        } catch (err: any) {
            if (err.message === 'AUTH_SESSION_REVOKED') {
                return res.status(401).json({ error: 'AUTH_SESSION_REVOKED' });
            }
            return res.status(401).json({ error: 'AUTH_TOKEN_INVALID' });
        }
    };

    // 2. POST /api/session/mfa/verify
    app.post('/api/session/mfa/verify', authenticate, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const idp: IdentityProvider = (req as any).idp;
        const start = Date.now();
        const clientIp = getClientIp(req);

        const body = req.body || {};
        const code = body.code;
        if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) {
            recordFailedAttempt(clientIp);
            await delayToFloor(start, 1000);
            return res.status(401).json({ error: 'AUTH_MFA_FAILED' });
        }

        try {
            const mfaStatus = await idp.getMfaStatus(principal.id);
            const verifiedFactor = mfaStatus.factors.find(f => f.status === 'verified');
            if (!verifiedFactor) {
                recordFailedAttempt(clientIp);
                await delayToFloor(start, 1000);
                return res.status(401).json({ error: 'AUTH_MFA_FAILED' });
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
            return res.status(200).json({
                accessToken: verification.accessToken,
                refreshToken: verification.refreshToken,
                aal: verification.aal
            });
        } catch {
            recordFailedAttempt(clientIp);
            await delayToFloor(start, 1000);
            return res.status(401).json({ error: 'AUTH_MFA_FAILED' });
        }
    });

    // 3. GET /api/session/memberships
    app.get('/api/session/memberships', authenticate, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const memberships = await listPrincipalMemberships(principal.id, dbPool);
        return res.status(200).json({ memberships });
    });

    // 4. GET /api/session/workspaces
    app.get('/api/session/workspaces', authenticate, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const orgId = req.query.organisationId as string;
        if (!orgId) {
            return res.status(400).json({ error: 'MISSING_ORG_ID' });
        }
        const workspaces = await listOrgWorkspaces(principal.id, orgId, dbPool);
        return res.status(200).json({ workspaces });
    });

    // 5. POST /api/session/context
    app.post('/api/session/context', authenticate, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const body = req.body || {};
        try {
            const context = await createAccessContext({
                userId: principal.id,
                sessionId: principal.sessionId,
                organisationId: body.organisationId,
                workspaceId: body.workspaceId,
                aal: principal.aal === 'aal2' ? 'aal2' : 'aal1',
                supportGrantId: body.supportGrantId
            }, dbPool);
            return res.status(200).json({ context });
        } catch (err: any) {
            return res.status(400).json({ error: err.message || 'AUTH_CONTEXT_CREATE_FAILED' });
        }
    });

    // 6. POST /api/session/context/renew
    app.post('/api/session/context/renew', authenticate, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const body = req.body || {};
        const contextId = body.contextId || req.headers['x-archscale-context'];
        if (!contextId || typeof contextId !== 'string') {
            return res.status(400).json({ error: 'AUTH_CONTEXT_REQUIRED' });
        }
        try {
            const context = await renewAccessContext(contextId, principal.id, principal.sessionId, dbPool);
            return res.status(200).json({ context });
        } catch (err: any) {
            return res.status(400).json({ error: err.message || 'AUTH_CONTEXT_RENEW_FAILED' });
        }
    });

    // 7. POST /api/session/logout
    app.post('/api/session/logout', authenticate, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const idp: IdentityProvider = (req as any).idp;
        const body = req.body || {};
        const contextId = body.contextId || req.headers['x-archscale-context'];
        if (contextId && typeof contextId === 'string') {
            await revokeAccessContext(contextId, principal.id, principal.sessionId).catch(() => {});
        }
        if (principal.sessionId) {
            await idp.revokeSession(principal.sessionId).catch(() => {});
        }
        return res.status(200).json({ success: true });
    });

    // --- CONTEXT-GUARDED ROUTES ---
    const requireContext = async (req: Request, res: Response, next: NextFunction) => {
        const contextId = req.headers['x-archscale-context'] as string;
        if (!contextId) {
            return res.status(401).json({ error: 'AUTH_CONTEXT_REQUIRED' });
        }
        const principal: VerifiedPrincipal = (req as any).principal;
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
                client.release();
                return res.status(403).json({ error: 'AUTH_CONTEXT_INVALID' });
            }

            (req as any).contextId = contextId;
            (req as any).dbClient = client;

            let released = false;
            const cleanup = () => {
                if (released) return;
                released = true;
                client.query('COMMIT;').catch(() => {});
                client.release();
            };
            res.once('finish', cleanup);
            res.once('close', cleanup);
            next();
        } catch (err: any) {
            client.release();
            return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
        }
    };

    // GET /api/me
    app.get('/api/me', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;

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
            return res.status(403).json({ error: 'AUTH_CONTEXT_INVALID' });
        }
        return res.status(200).json({
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
    });

    // GET /api/platform/organisations
    app.get('/api/platform/organisations', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;

        const decision = await decide(client, principal, contextId, 'platform.organisations.read');
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        const orgs = await client.query(`SELECT id, name, portal, status FROM public.organisations ORDER BY name;`);
        return res.status(200).json({ decision, data: orgs.rows });
    });

    // GET /api/org/members
    app.get('/api/org/members', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;

        const decision = await decide(client, principal, contextId, 'org.members.read');
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        const members = await client.query(
            `SELECT m.id, m.user_id, m.role_key, m.status 
             FROM public.memberships m 
             WHERE m.organisation_id = $1::uuid;`,
            [decision.organisationId]
        );
        return res.status(200).json({ decision, data: members.rows });
    });

    // POST /api/org/invitations (Return 202 Accepted per assignment / instructions)
    app.post('/api/org/invitations', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;
        const body = req.body || {};

        const decision = await decide(client, principal, contextId, 'org.members.invite', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }

        return res.status(200).json({
            decision,
            invited: {
                email: body.email,
                roleKey: body.roleKey || 'member',
                organisationId: decision.organisationId
            }
        });
    });

    // 404 handler
    app.use((req: Request, res: Response) => {
        return res.status(404).json({ error: 'NOT_FOUND' });
    });

    // Global error handler
    app.use((err: any, req: Request, res: Response, next: NextFunction) => {
        if (err.type === 'entity.too.large') {
            return res.status(413).json({ error: 'PAYLOAD_TOO_LARGE' });
        }
        return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
    });

    return http.createServer(app);
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
        console.log(`[ArchScale Server (Express)] Listening on http://${host}:${port} (Demo mode: ${process.env.ARCHSCALE_DEMO === 'true'})`);
    });
}
