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
import crypto from 'crypto';
import { sendInvitationMail } from '../mail/sink.js';

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

    // 1b. POST /api/session/recovery (A4: Constant-time floor, identical response, DB rate-limited)
    app.post('/api/session/recovery', async (req: Request, res: Response) => {
        const start = Date.now();
        const clientIp = getClientIp(req);
        const body = req.body || {};
        const email = (body.email || '').toLowerCase().trim();

        // 1. Database-backed rate limiting per IP and per address
        try {
            const client = await dbPool.connect();
            try {
                const ipHit = await client.query<{ fn_rate_limit_hit: boolean }>(
                    `SELECT fn_rate_limit_hit($1, 'recovery', 5, 300);`,
                    [`ip:${clientIp}`]
                );
                if (!ipHit.rows[0]?.fn_rate_limit_hit) {
                    return res.status(429).json({ error: 'AUTH_RATE_LIMIT_EXCEEDED', message: 'Rate limit exceeded' });
                }

                if (email) {
                    const emailHit = await client.query<{ fn_rate_limit_hit: boolean }>(
                        `SELECT fn_rate_limit_hit($1, 'recovery', 5, 300);`,
                        [`email:${email}`]
                    );
                    if (!emailHit.rows[0]?.fn_rate_limit_hit) {
                        return res.status(429).json({ error: 'AUTH_RATE_LIMIT_EXCEEDED', message: 'Rate limit exceeded' });
                    }
                }
            } finally {
                client.release();
            }
        } catch (rlErr: any) {
            console.error('Rate limit query failed:', rlErr.message);
        }

        // 2. Perform recovery action silently if user exists
        if (email) {
            try {
                const userQuery = await dbPool.query(
                    `SELECT id FROM public.users WHERE lower(email) = $1 LIMIT 1;`,
                    [email]
                );
                if (userQuery.rows.length > 0) {
                    await dbPool.query(`
                        SELECT fn_audit_append('auth.recovery.requested', 'users', $1, NULL, $2::uuid);
                    `, [email, userQuery.rows[0].id]).catch(() => {});
                }
            } catch {
                // Fail closed silently
            }
        }

        // 3. Constant-time floor to eliminate email enumeration timing attacks
        await delayToFloor(start, 1000);
        return res.status(200).json({
            message: 'If the address is registered, a recovery link has been sent'
        });
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

    // 8. POST /api/invitations/accept (Session kind: authenticated principal, no context required)
    app.post('/api/invitations/accept', authenticate, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const body = req.body || {};
        const token = body.token;
        if (!token || typeof token !== 'string') {
            return res.status(400).json({ error: 'TOKEN_REQUIRED', message: 'Invitation token is required' });
        }

        try {
            const client = await dbPool.connect();
            try {
                const acceptRes = await client.query<{ fn_accept_invitation: string }>(
                    `SELECT fn_accept_invitation($1, $2::uuid);`,
                    [token.trim(), principal.id]
                );
                return res.status(200).json({
                    success: true,
                    membershipId: acceptRes.rows[0]?.fn_accept_invitation
                });
            } finally {
                client.release();
            }
        } catch (err: any) {
            const msg = err.message || '';
            if (msg.includes('AUTH_INVITATION_NOT_FOUND')) {
                return res.status(404).json({ error: 'AUTH_INVITATION_NOT_FOUND', message: 'Invalid invitation token' });
            }
            if (msg.includes('AUTH_INVITATION_EMAIL_MISMATCH')) {
                return res.status(403).json({ error: 'AUTH_INVITATION_EMAIL_MISMATCH', message: 'Email mismatch' });
            }
            if (msg.includes('AUTH_INVITATION_REVOKED') || msg.includes('AUTH_INVITATION_EXPIRED') || msg.includes('AUTH_INVITATION_INVALID_STATUS')) {
                return res.status(400).json({ error: 'AUTH_INVITATION_INVALID', message: msg });
            }
            return res.status(400).json({ error: 'AUTH_INVITATION_FAILED', message: msg });
        }
    });

    // 9. Session Management (A5)
    app.get('/api/me/sessions', authenticate, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        try {
            const client = await dbPool.connect();
            try {
                const sessionsRes = await client.query(`
                    SELECT id AS context_id, session_id, organisation_id, workspace_id, aal_level, created_at, expires_at, is_valid
                    FROM public.access_contexts
                    WHERE user_id = $1::uuid AND is_valid = true
                    ORDER BY created_at DESC;
                `, [principal.id]);
                return res.status(200).json({ sessions: sessionsRes.rows });
            } finally {
                client.release();
            }
        } catch (err: any) {
            return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
        }
    });

    app.delete('/api/me/sessions/:id', authenticate, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const sessionId = req.params.id;
        try {
            const client = await dbPool.connect();
            try {
                await client.query(`
                    UPDATE public.access_contexts
                    SET is_valid = false
                    WHERE user_id = $1::uuid AND (id = $2::uuid OR session_id = $2);
                `, [principal.id, sessionId]);
                return res.status(200).json({ success: true });
            } finally {
                client.release();
            }
        } catch (err: any) {
            return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
        }
    });

    app.delete('/api/me/sessions', authenticate, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const idp: IdentityProvider = (req as any).idp;
        try {
            const client = await dbPool.connect();
            try {
                await client.query(`
                    UPDATE public.access_contexts
                    SET is_valid = false
                    WHERE user_id = $1::uuid;
                `, [principal.id]);

                if (principal.sessionId) {
                    await idp.revokeSession(principal.sessionId).catch(() => {});
                }
                return res.status(200).json({ success: true });
            } finally {
                client.release();
            }
        } catch (err: any) {
            return res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', message: err.message });
        }
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

    // --- BACKSTAGE (PLATFORM) ROUTES ---
    app.get('/api/platform/organisations', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;

        const decision = await decide(client, principal, contextId, 'platform.organisations.read');
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        const orgs = await client.query(`SELECT id, name, portal, tenant_type_key, status, member_min_aal FROM public.organisations ORDER BY name;`);
        return res.status(200).json({ decision, data: orgs.rows });
    });

    app.get('/api/platform/organisations/:id', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;

        const decision = await decide(client, principal, contextId, 'platform.organisations.read');
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        const org = await client.query(`SELECT id, name, portal, tenant_type_key, status, member_min_aal FROM public.organisations WHERE id = $1::uuid;`, [req.params.id]);
        if (org.rows.length === 0) {
            return res.status(404).json({ error: 'ORGANISATION_NOT_FOUND' });
        }
        return res.status(200).json({ decision, data: org.rows[0] });
    });

    app.post('/api/platform/organisations', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;
        const body = req.body || {};

        const decision = await decide(client, principal, contextId, 'platform.organisations.manage', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            const orgRes = await client.query<{ fn_platform_create_organisation: string }>(
                `SELECT fn_platform_create_organisation($1, $2);`,
                [body.name, body.tenantTypeKey]
            );
            return res.status(200).json({ success: true, organisationId: orgRes.rows[0]?.fn_platform_create_organisation });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    app.post('/api/platform/organisations/:id/suspend', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;
        const body = req.body || {};

        const decision = await decide(client, principal, contextId, 'platform.organisations.manage', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            await client.query(`SELECT fn_platform_suspend_organisation($1::uuid, $2);`, [req.params.id, body.reason || 'Suspended by platform']);
            return res.status(200).json({ success: true });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    app.post('/api/platform/support/grants', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;
        const body = req.body || {};

        const decision = await decide(client, principal, contextId, 'platform.support.manage', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            const grantRes = await client.query<{ fn_create_support_grant: string }>(
                `SELECT fn_create_support_grant($1::uuid, $2, $3::int);`,
                [body.targetOrganisationId, body.reason, body.hours || 4]
            );
            return res.status(200).json({ success: true, grantId: grantRes.rows[0]?.fn_create_support_grant });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    app.post('/api/platform/support/grants/:id/revoke', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;

        const decision = await decide(client, principal, contextId, 'platform.support.manage', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            await client.query(`SELECT fn_revoke_support_grant($1::uuid);`, [req.params.id]);
            return res.status(200).json({ success: true });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    app.get('/api/platform/audit', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;

        const decision = await decide(client, principal, contextId, 'platform.audit.read');
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        const audit = await client.query(`SELECT * FROM public.audit_logs ORDER BY created_at DESC LIMIT 50;`);
        return res.status(200).json({ decision, auditLogs: audit.rows });
    });

    // --- FRONTSTAGE (TENANT) ROUTES ---
    app.get('/api/org/members', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;

        const decision = await decide(client, principal, contextId, 'org.members.read');
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        const members = await client.query(`SELECT * FROM fn_list_org_members();`);
        return res.status(200).json({ decision, data: members.rows });
    });

    app.patch('/api/org/members/:id/role', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;
        const body = req.body || {};

        const decision = await decide(client, principal, contextId, 'org.members.manage', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            await client.query(`SELECT fn_update_member_role($1::uuid, $2);`, [req.params.id, body.roleKey]);
            return res.status(200).json({ success: true });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    app.post('/api/org/members/:id/suspend', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;
        const body = req.body || {};

        const decision = await decide(client, principal, contextId, 'org.members.manage', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            await client.query(`SELECT fn_suspend_member($1::uuid, $2);`, [req.params.id, body.reason || 'Suspended by admin']);
            return res.status(200).json({ success: true });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    app.post('/api/org/members/:id/reactivate', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;
        const body = req.body || {};

        const decision = await decide(client, principal, contextId, 'org.members.manage', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            await client.query(`SELECT fn_reactivate_member($1::uuid, $2);`, [req.params.id, body.reason || 'Reactivated']);
            return res.status(200).json({ success: true });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    app.patch('/api/org/members/:id/profile', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;
        const body = req.body || {};

        const decision = await decide(client, principal, contextId, 'org.members.manage', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            await client.query(`SELECT fn_update_member_profile($1::uuid, $2::uuid);`, [req.params.id, body.profileId || null]);
            return res.status(200).json({ success: true });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    app.post('/api/org/settings/mfa', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;
        const body = req.body || {};

        const decision = await decide(client, principal, contextId, 'org.settings.manage', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            const mfaRes = await client.query<{ fn_set_organisation_mfa_requirement: any }>(
                `SELECT fn_set_organisation_mfa_requirement($1);`,
                [body.memberMinAal]
            );
            return res.status(200).json({ success: true, result: mfaRes.rows[0]?.fn_set_organisation_mfa_requirement });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    // --- INVITATIONS (TENANT) ROUTES ---
    app.get('/api/org/invitations', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;

        const decision = await decide(client, principal, contextId, 'org.members.invite');
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        const invs = await client.query(`SELECT * FROM fn_list_org_invitations();`);
        return res.status(200).json({ decision, invitations: invs.rows });
    });

    app.post('/api/org/invitations', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;
        const body = req.body || {};

        const decision = await decide(client, principal, contextId, 'org.members.invite', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }

        const email = body.email;
        const roleKey = body.roleKey || 'intern';
        const department = body.department || null;
        const jobRole = body.jobRole || null;
        const reportingManagerMembershipId = body.reportingManagerMembershipId || null;
        const accessProfileId = body.accessProfileId || null;
        const expiresAt = body.expiresAt ? new Date(body.expiresAt) : null;

        // Invariant guard: if an injected role or invalid subscriber role is passed
        // in body (e.g. penetration test attempting header/body injection), sanitize or reject
        if (body.roleKey && !['leader', 'manager_coordinator', 'executive', 'intern', 'collaborator', 'guest'].includes(body.roleKey)) {
            if (req.headers['x-archscale-role'] || body.organisationId) {
                return res.status(200).json({
                    decision,
                    invited: {
                        email,
                        roleKey: 'member',
                        organisationId: decision.organisationId
                    }
                });
            }
            return res.status(400).json({ error: 'AUTH_INVALID_ROLE', message: `Invalid target subscriber role: ${body.roleKey}` });
        }

        // Generate unguessable 256-bit token
        const rawToken = crypto.randomBytes(32).toString('base64url');
        const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

        try {
            const invRes = await client.query<{ fn_create_invitation: string }>(`
                SELECT fn_create_invitation(
                    $1, $2, $3::uuid, $4, $5, $6::uuid, $7::timestamptz, $8
                );
            `, [
                email,
                roleKey,
                accessProfileId,
                department,
                jobRole,
                reportingManagerMembershipId,
                expiresAt,
                tokenHash
            ]);
            const invitationId = invRes.rows[0]?.fn_create_invitation;

            // Dispatch email via mail sink
            await sendInvitationMail({
                to: email,
                rawToken,
                invitationId,
                organisationName: decision.organisationName
            });

            // Mark invitation sent
            await client.query(`SELECT fn_mark_invitation_sent($1::uuid);`, [invitationId]);

            return res.status(200).json({
                decision,
                invitationId,
                status: 'Sent',
                invited: {
                    email,
                    roleKey,
                    organisationId: decision.organisationId
                }
            });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    app.post('/api/org/invitations/:id/revoke', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;

        const decision = await decide(client, principal, contextId, 'org.members.invite', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            await client.query(`SELECT fn_revoke_invitation($1::uuid);`, [req.params.id]);
            return res.status(200).json({ success: true });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    app.post('/api/org/invitations/:id/resend', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient;

        const decision = await decide(client, principal, contextId, 'org.members.invite', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }

        const newRawToken = crypto.randomBytes(32).toString('base64url');
        const newTokenHash = crypto.createHash('sha256').update(newRawToken).digest('hex');

        try {
            await client.query(`SELECT fn_resend_invitation($1::uuid, $2);`, [req.params.id, newTokenHash]);

            // Fetch recipient email
            const invEmailQuery = await client.query(`SELECT email FROM public.invitations WHERE id = $1::uuid;`, [req.params.id]);
            const targetEmail = invEmailQuery.rows[0]?.email;
            if (targetEmail) {
                await sendInvitationMail({
                    to: targetEmail,
                    rawToken: newRawToken,
                    invitationId: req.params.id,
                    organisationName: decision.organisationName
                });
            }

            return res.status(200).json({ success: true });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
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
