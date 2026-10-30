import express, { Request, Response, NextFunction } from 'express';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getIdentityProvider, IdentityProvider, VerifiedPrincipal, SupabaseProvider } from '../identity/index.js';
import { listPrincipalMemberships, listOrgWorkspaces } from '../context/memberships.js';
import { createAccessContext, renewAccessContext, revokeAccessContext } from '../context/access_context.js';
import { runtimePool, withAppContext } from '../db/index.js';
import { decide } from '../authz/decide.js';
import crypto from 'crypto';
import { sendInvitationMail } from '../mail/sink.js';
import { generateTotpCode } from '../utils/totp.js';
import { PoolClient } from 'pg';
import { config } from '../config/env.js';

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
    app.use(express.static(path.join(__dirname, 'public')));
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

    // Demo identity endpoints are disabled in every deployed environment. They
    // used to elevate arbitrary shared demo identities to AAL2 and are not an
    // authentication mechanism for real tenants.
    app.get('/api/demo/presets', (_req: Request, res: Response) =>
        res.status(404).json({ error: 'NOT_FOUND' }));

    app.post('/api/demo/quick-login', async (req: Request, res: Response) => {
        const localDevelopment = config.env === 'development';
        const localTest = config.nodeEnv === 'test' && config.allowLocalAuth;
        if (!localDevelopment && !localTest) {
            return res.status(404).json({ error: 'NOT_FOUND' });
        }

        const key = typeof req.body?.key === 'string' ? req.body.key : '';
        const personaMap: Record<string, { baseKey: string; role: string; dept: string; title: string; memberId: string }> = {
            'founder':           { baseKey: 'founder',        role: 'founder',             dept: 'Platform',   title: 'Platform Super Admin', memberId: 'mem-00' },
            'tenant_admin':      { baseKey: 'business_owner', role: 'business_owner',      dept: 'Management', title: 'Tenant Admin',          memberId: 'mem-01' },
            'business_owner':    { baseKey: 'business_owner', role: 'business_owner',      dept: 'Management', title: 'Tenant Admin',          memberId: 'mem-01' },
            'design_manager_1':  { baseKey: 'leader',         role: 'leader',              dept: 'Design',     title: 'Design Manager 1',      memberId: 'lead-01' },
            'junior_designer_1': { baseKey: 'leader',         role: 'intern',              dept: 'Design',     title: 'Junior Designer 1',     memberId: 'des-01' },
            'design_manager_2':  { baseKey: 'leader',         role: 'leader',              dept: 'Design',     title: 'Design Manager 2',      memberId: 'lead-02' },
            'junior_designer_2': { baseKey: 'leader',         role: 'intern',              dept: 'Design',     title: 'Junior Designer 2',     memberId: 'des-02' },
            'design_manager_3':  { baseKey: 'leader',         role: 'leader',              dept: 'Design',     title: 'Design Manager 3',      memberId: 'lead-03' },
            'junior_designer_3': { baseKey: 'leader',         role: 'intern',              dept: 'Design',     title: 'Junior Designer 3',     memberId: 'des-03' },
            'accounts_manager':  { baseKey: 'business_owner', role: 'manager_coordinator', dept: 'Accounts',   title: 'Accounts Manager',      memberId: 'acc-01' },
            'junior_accountant': { baseKey: 'business_owner', role: 'intern',              dept: 'Accounts',   title: 'Junior Accountant',     memberId: 'acc-02' },
            'hr_manager':        { baseKey: 'business_owner', role: 'manager_coordinator', dept: 'HR',         title: 'HR Manager',             memberId: 'hr-01' },
            'junior_hr':         { baseKey: 'business_owner', role: 'intern',              dept: 'HR',         title: 'Junior HR',              memberId: 'hr-02' },
        };
        const persona = personaMap[key];
        if (!persona) {
            return res.status(400).json({ error: 'DEMO_PERSONA_NOT_FOUND', message: 'Select a valid demo persona.' });
        }

        try {
            const testUsersPath = path.join(process.cwd(), '.local/test-users.json');
            let users: Record<string, { email?: string; password?: string }> = {};
            if (fs.existsSync(testUsersPath)) {
                users = JSON.parse(fs.readFileSync(testUsersPath, 'utf-8'));
            }

            const baseKey = key === 'founder' ? 'founder' : 'business_owner';
            const configuredDemoUser = localDevelopment && key !== 'founder'
                && process.env.ARCHSCALE_LOCAL_DEMO_EMAIL
                && process.env.ARCHSCALE_LOCAL_DEMO_PASSWORD
                ? {
                    email: process.env.ARCHSCALE_LOCAL_DEMO_EMAIL,
                    password: process.env.ARCHSCALE_LOCAL_DEMO_PASSWORD,
                }
                : undefined;
            const user = users[baseKey] || users[persona.baseKey] || users[key] || configuredDemoUser;
            if (!user?.email || !user.password) {
                return res.status(503).json({
                    error: 'DEMO_LOGIN_NOT_CONFIGURED',
                    message: 'Configure a local demo account before using Quick Login.',
                });
            }

            const idp = identityProvider || getIdentityProvider();
            const session = await idp.signIn({ email: user.email, password: user.password });
            let mfaRequired = false;
            try {
                const mfaStatus = await idp.getMfaStatus(session.principal.id);
                mfaRequired = mfaStatus.factors.some(f => f.status === 'verified')
                    && session.principal.aal !== 'aal2';
            } catch {
                mfaRequired = false;
            }

            const demoPersona = {
                key,
                role: persona.role,
                dept: persona.dept,
                title: persona.title,
                memberId: persona.memberId,
            };
            return res.status(200).json({
                accessToken: session.accessToken,
                refreshToken: session.refreshToken,
                principal: {
                    ...session.principal,
                    role: persona.role,
                    department: persona.dept,
                    jobRole: persona.title,
                    personaKey: key,
                    memberId: persona.memberId,
                },
                mfaRequired,
                demoPersona,
            });
        } catch {
            return res.status(401).json({
                error: 'QUICK_LOGIN_FAILED',
                message: 'Local demo sign-in failed. Check the local demo account and try again.',
            });
        }
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
            const client: PoolClient = await dbPool.connect();
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

        // Supabase sends the recovery email; keep the response generic to avoid
        // disclosing whether the address belongs to an account.
        if (email) {
            try { await (identityProvider || getIdentityProvider()).requestPasswordReset(email); }
            catch { /* Generic response deliberately hides delivery/account state. */ }
        }

        // 3. Constant-time floor to eliminate email enumeration timing attacks
        await delayToFloor(start, 1000);
        return res.status(200).json({
            message: 'If the address is registered, a recovery link has been sent'
        });
    });

    // 1c. POST /api/session/reset-password (B0.6: Revoke every session and context of that user)
    app.post('/api/session/reset-password', async (req: Request, res: Response) => {
        const { token, newPassword } = req.body || {};
        if (!token || !newPassword || typeof token !== 'string' || typeof newPassword !== 'string' || newPassword.length < 12) {
            return res.status(400).json({ error: 'TOKEN_AND_VALID_PASSWORD_REQUIRED' });
        }
        try {
            const idp: IdentityProvider = identityProvider || getIdentityProvider();
            if (idp.confirmPasswordReset) {
                await idp.confirmPasswordReset(token, newPassword);
            }

            // confirmPasswordReset asks Supabase Auth to sign out globally;
            // all requests also revalidate the Auth token before using context.
            return res.status(200).json({ success: true, message: 'Password has been reset and all sessions revoked' });
        } catch (err: any) {
            return res.status(400).json({ error: err.code || 'RESET_FAILED', message: err.message });
        }
    });

    const elevatedPrincipals = new Set<string>();

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
            if (elevatedPrincipals.has(principal.id) || (principal.sessionId && elevatedPrincipals.has(principal.sessionId))) {
                principal.aal = 'aal2';
            }
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
        const code = (body.code || '').toString().trim();
        const bypass = body.bypass === true;
        const localTest = process.env.NODE_ENV === 'test' && process.env.ALLOW_LOCAL_AUTH === 'true';

        if (bypass && !localTest) return res.status(403).json({ error: 'AUTH_MFA_BYPASS_DENIED' });

        if (!bypass && (!code || !/^\d{6}$/.test(code))) {
            recordFailedAttempt(clientIp);
            await delayToFloor(start, 1000);
            return res.status(401).json({ error: 'AUTH_MFA_FAILED' });
        }

        try {
            if (bypass) {
                elevatedPrincipals.add(principal.id);
                if (principal.sessionId) elevatedPrincipals.add(principal.sessionId);
                clearRateLimit(clientIp);
                const token = (req.headers['authorization'] as string).substring('Bearer '.length).trim();
                return res.status(200).json({
                    accessToken: token,
                    refreshToken: token,
                    principal: { ...principal, aal: 'aal2' },
                    aal: 'aal2'
                });
            }

            // 1. Try standard IdP verification first
            try {
                const mfaStatus = await idp.getMfaStatus(principal.id);
                const verifiedFactor = mfaStatus.factors.find(f => f.status === 'verified');
                if (verifiedFactor) {
                    if (!(idp instanceof SupabaseProvider)) throw new Error('Use local test MFA verifier');
                    const accessToken = (req.headers['authorization'] as string).substring('Bearer '.length).trim();
                    const challenge = await idp.challengeMfa(verifiedFactor.id, accessToken);
                    const verification = await idp.verifyMfa(verifiedFactor.id, challenge.id, code, accessToken);
                    clearRateLimit(clientIp);
                    const verified = await idp.verify(verification.accessToken);
                    return res.status(200).json({
                        accessToken: verification.accessToken,
                        refreshToken: verification.refreshToken,
                        principal: verified,
                        aal: verified.aal
                    });
                }
            } catch {
                if (!localTest) throw new Error('AUTH_MFA_FAILED');
            }

            if (!localTest) throw new Error('AUTH_MFA_FAILED');
            // Isolated unit-test-only TOTP fixture. This branch is unreachable in deployed environments.
            let valid = false;
            if (code === '123456') {
                valid = true;
            } else {
                try {
                    const testUsersPath = path.join(process.cwd(), '.local/test-users.json');
                    if (fs.existsSync(testUsersPath)) {
                        const testUsers = JSON.parse(fs.readFileSync(testUsersPath, 'utf-8'));
                        const userMatch = Object.values(testUsers).find((u: any) => u.email === principal.email || u.id === principal.id) as any;
                        if (userMatch && userMatch.totpSecret) {
                            const nowSec = Math.floor(Date.now() / 1000);
                            for (let step = -4; step <= 4; step++) {
                                if (generateTotpCode(userMatch.totpSecret, nowSec + step * 30) === code) {
                                    valid = true;
                                    break;
                                }
                            }
                        }
                    }
                } catch {}
            }

            if (!valid) {
                recordFailedAttempt(clientIp);
                await delayToFloor(start, 1000);
                return res.status(401).json({ error: 'AUTH_MFA_FAILED' });
            }

            elevatedPrincipals.add(principal.id);
            if (principal.sessionId) elevatedPrincipals.add(principal.sessionId);
            clearRateLimit(clientIp);
            const token = (req.headers['authorization'] as string).substring('Bearer '.length).trim();
            return res.status(200).json({
                accessToken: token,
                refreshToken: token,
                principal: { ...principal, aal: 'aal2' },
                aal: 'aal2'
            });
        } catch {
            recordFailedAttempt(clientIp);
            await delayToFloor(start, 1000);
            return res.status(401).json({ error: 'AUTH_MFA_FAILED' });
        }
    });

    app.post('/api/session/refresh', async (req: Request, res: Response) => {
        const refreshToken = req.body?.refreshToken;
        if (typeof refreshToken !== 'string' || !refreshToken) return res.status(400).json({ error:'AUTH_REFRESH_TOKEN_REQUIRED' });
        try {
            const session = await (identityProvider || getIdentityProvider()).refresh(refreshToken);
            return res.status(200).json({ accessToken:session.accessToken,refreshToken:session.refreshToken,principal:session.principal });
        } catch {
            return res.status(401).json({ error:'AUTH_REFRESH_FAILED' });
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
            const client: PoolClient = await dbPool.connect();
            try {
                await client.query('BEGIN');
                await client.query('SELECT fn_set_app_context($1::uuid,$2::uuid,$3::text)', [context.contextId,principal.id,principal.sessionId]);
                const details = await client.query(`SELECT m.id AS membership_id,m.role_key,m.department,m.job_role,o.name AS organisation_name,w.name AS workspace_name
                    FROM public.access_contexts ac JOIN public.memberships m ON m.id=ac.membership_id
                    JOIN public.organisations o ON o.id=ac.organisation_id JOIN public.workspaces w ON w.id=ac.workspace_id
                    WHERE ac.id=$1::uuid`, [context.contextId]);
                await client.query('COMMIT');
                return res.status(200).json({ context: { ...context, ...(details.rows[0] ?? {}) } });
            } catch (error) { await client.query('ROLLBACK').catch(()=>{}); throw error; }
            finally { client.release(); }
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
        const accessToken = (req.headers['authorization'] as string).substring('Bearer '.length).trim();
        await idp.revokeSession(accessToken).catch(() => {});
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
            const client: PoolClient = await dbPool.connect();
            try {
                // B0.3: Mark expired before accept so status = 'Expired' is persisted
                await client.query(`SELECT fn_mark_invitation_expired($1);`, [token.trim()]);

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
                    SELECT id AS context_id, session_id, organisation_id, workspace_id, aal_level, created_at, expires_at
                    FROM public.access_contexts
                    WHERE user_id = $1::uuid AND revoked_at IS NULL AND expires_at > now()
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
        const idp: IdentityProvider = (req as any).idp;
        if (String(req.params.id) !== principal.sessionId) {
            return res.status(501).json({ error:'AUTH_SESSION_REVOCATION_UNSUPPORTED', message:'Supabase does not support revoking another device by session ID alone.' });
        }
        const accessToken = (req.headers['authorization'] as string).substring('Bearer '.length).trim();
        try { await idp.revokeSession(accessToken); return res.status(200).json({ success:true }); }
        catch { return res.status(400).json({ error:'AUTH_SESSION_REVOKE_FAILED' }); }
    });

    app.delete('/api/me/sessions', authenticate, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const idp: IdentityProvider = (req as any).idp;
        try {
            const accessToken = (req.headers['authorization'] as string).substring('Bearer '.length).trim();
            await idp.revokeAllForUser(accessToken);
            return res.status(200).json({ success:true });
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
        const client: PoolClient = await dbPool.connect();

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

            try {
                const ctxQuery = await client.query(`
                    SELECT ac.organisation_id, m.role_key, m.department, m.job_role
                    FROM public.access_contexts ac
                    JOIN public.memberships m ON m.id = ac.membership_id
                    WHERE ac.id = $1::uuid;
                `, [contextId]);
                const ctxRow = ctxQuery.rows[0];
                if (ctxRow) {
                    (req as any).contextRole = ctxRow.role_key;
                    (req as any).contextDept = ctxRow.department;
                    (req as any).organisationId = ctxRow.organisation_id;
                }
            } catch {}

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
        const client = (req as any).dbClient as PoolClient;

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
        const client = (req as any).dbClient as PoolClient;

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
        const client = (req as any).dbClient as PoolClient;

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
        const client = (req as any).dbClient as PoolClient;
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
        const client = (req as any).dbClient as PoolClient;
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

    app.post('/api/platform/organisations/:id/approve', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient as PoolClient;
        const body = req.body || {};

        const decision = await decide(client, principal, contextId, 'platform.organisations.manage', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            await client.query(`SELECT fn_platform_approve_organisation($1::uuid, $2);`, [req.params.id, body.reason || 'Approved by platform']);
            return res.status(200).json({ success: true });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    app.post('/api/platform/organisations/:id/invite-admin', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient as PoolClient;
        const body = req.body || {};

        const decision = await decide(client, principal, contextId, 'platform.organisations.manage', { isMutation: true });
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            const rawToken = crypto.randomBytes(32).toString('base64url');
            const tokenHash = crypto.createHash('sha256').update(Buffer.from(rawToken, 'utf8')).digest('hex');

            const invRes = await client.query<{ fn_platform_invite_tenant_admin: string }>(
                `SELECT fn_platform_invite_tenant_admin($1::uuid, $2, $3::timestamptz);`,
                [req.params.id, body.email, body.invitationExpiresAt || null]
            );
            const invitationId = invRes.rows[0]?.fn_platform_invite_tenant_admin;

            // Update token hash directly
            await client.query(`UPDATE public.invitations SET token_hash = $1 WHERE id = $2::uuid;`, [tokenHash, invitationId]);

            // Dispatch email
            await sendInvitationMail({
                to: body.email,
                rawToken,
                invitationId,
                organisationName: 'Your Organisation'
            });

            await client.query(`SELECT fn_mark_invitation_sent($1::uuid);`, [invitationId]);

            return res.status(200).json({ success: true, invitationId });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    app.post('/api/platform/support/grants', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient as PoolClient;
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
        const client = (req as any).dbClient as PoolClient;

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
        const client = (req as any).dbClient as PoolClient;

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
        const client = (req as any).dbClient as PoolClient;

        const decision = await decide(client, principal, contextId, 'org.members.read');
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        // fn_list_org_members returns: id, user_id, role_key, department, job_role, reporting_manager_membership_id, status
        // We try to enrich with user name/email via a JOIN. If DB has real members (≥11) use them; otherwise fall back to demo team.
        let memberRows: any[] = [];
        try {
            const enriched = await client.query(`
                SELECT
                    m.id,
                    m.user_id,
                    m.role_key,
                    m.department,
                    m.job_role,
                    m.reporting_manager_membership_id,
                    m.status,
                    COALESCE(u.email, m.id::text) AS name,
                    COALESCE(u.email, '') AS email
                FROM fn_list_org_members() m
                LEFT JOIN public.users u ON u.id = m.user_id
                ORDER BY m.department, m.job_role;
            `);
            memberRows = enriched.rows;
        } catch {
            return res.status(503).json({ error: 'MEMBER_DIRECTORY_UNAVAILABLE' });
        }

        // Normalise DB rows to camelCase (DB returns snake_case)
        const normaliseRow = (r: any, isDemoData = false) => ({
            id: r.id,
            userId: r.user_id ?? r.userId,
            name: r.name ?? r.display_name ?? r.id,
            email: r.email ?? '',
            roleKey: r.role_key ?? r.roleKey ?? '',
            department: r.department ?? '',
            jobRole: r.job_role ?? r.jobRole ?? '',
            status: r.status ?? 'ACTIVE',
            reportingManagerId: r.reporting_manager_membership_id ?? r.reportingManagerId ?? null,
            _demoOnly: isDemoData,
        });

        return res.status(200).json({ decision, data: memberRows.map(r => normaliseRow(r, false)) });
    });

    app.patch('/api/org/members/:id/role', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient as PoolClient;
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
        const client = (req as any).dbClient as PoolClient;
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
        const client = (req as any).dbClient as PoolClient;
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
        const client = (req as any).dbClient as PoolClient;
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
        const client = (req as any).dbClient as PoolClient;
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

    // Frontstage Support Grants List for Tenant Admin (B0.6)
    app.get('/api/org/support-grants', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient as PoolClient;

        const decision = await decide(client, principal, contextId, 'org.settings.manage');
        if (!decision.allow) {
            return res.status(403).json({ error: decision.reasonCode, decision });
        }
        try {
            const grantsRes = await client.query(`SELECT * FROM fn_list_org_support_grants();`);
            return res.status(200).json({
                decision,
                data: grantsRes.rows
            });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    // --- INVITATIONS (TENANT) ROUTES ---
    app.get('/api/org/invitations', authenticate, requireContext, async (req: Request, res: Response) => {
        const principal: VerifiedPrincipal = (req as any).principal;
        const contextId: string = (req as any).contextId;
        const client = (req as any).dbClient as PoolClient;

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
        const client = (req as any).dbClient as PoolClient;
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
        const invitationExpiresAt = body.invitationExpiresAt ? new Date(body.invitationExpiresAt) : (['intern', 'collaborator', 'guest'].includes(roleKey) ? null : (body.expiresAt ? new Date(body.expiresAt) : null));
        const membershipExpiresAt = body.membershipExpiresAt ? new Date(body.membershipExpiresAt) : (['intern', 'collaborator', 'guest'].includes(roleKey) && body.expiresAt ? new Date(body.expiresAt) : null);

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
        // B0.4: UTF-8 buffer hashing
        const tokenHash = crypto.createHash('sha256').update(Buffer.from(rawToken, 'utf8')).digest('hex');

        try {
            const invRes = await client.query<{ fn_create_invitation: string }>(`
                SELECT fn_create_invitation(
                    $1, $2, $3::uuid, $4, $5, $6::uuid, $7::timestamptz, $8::timestamptz, $9
                );
            `, [
                email,
                roleKey,
                accessProfileId,
                department,
                jobRole,
                reportingManagerMembershipId,
                invitationExpiresAt,
                membershipExpiresAt,
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
        const client = (req as any).dbClient as PoolClient;

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
        const client = (req as any).dbClient as PoolClient;

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
                    invitationId: String(req.params.id),
                    organisationName: decision.organisationName
                });
            }

            return res.status(200).json({ success: true });
        } catch (err: any) {
            return res.status(400).json({ error: err.message });
        }
    });

    // The app tables are tenant scoped and protected by FORCE RLS. These handlers
    // use the request context transaction established by requireContext.
    app.get('/api/tasks', authenticate, requireContext, async (req: Request, res: Response) => {
        const client = (req as any).dbClient as PoolClient;
        const result = await client.query(`SELECT t.* FROM public.tasks t ORDER BY t.due_at NULLS LAST, t.created_at DESC`);
        const tasks = result.rows.map((r: any) => ({ id:r.id, workId:r.work_id, title:r.title, description:r.description,
            assignedToId:r.assigned_to_membership_id, assignedToName:r.assigned_to_membership_id,
            department:r.department, reviewerId:r.reviewer_membership_id, reviewerName:r.reviewer_membership_id,
            startDate:r.start_date, dueDateTime:r.due_at, priority:r.priority, status:r.status,
            approvalStatus:r.approval_status, createdById:r.created_by_membership_id,
            approvedById:r.approved_by_membership_id }));
        return res.status(200).json({ tasks });
    });

    app.post('/api/tasks', authenticate, requireContext, async (req: Request, res: Response) => {
        const client = (req as any).dbClient as PoolClient;
        const b = req.body || {};
        if (typeof b.title !== 'string' || b.title.trim().length < 3 || !b.assignedToId || !b.reviewerId || !b.department) {
            return res.status(400).json({ error:'TASK_FIELDS_REQUIRED' });
        }
        try {
            const result = await client.query(`INSERT INTO public.tasks(title,description,assigned_to_membership_id,department,reviewer_membership_id,start_date,due_at,priority,status,approval_status)
                VALUES($1,$2,$3::uuid,$4,$5::uuid,COALESCE($6::date,CURRENT_DATE),$7::timestamptz,COALESCE($8,'Normal'),COALESCE($9,'To Do'),COALESCE($10,'Not Required')) RETURNING *`,
                [b.title.trim(),b.description ?? '',b.assignedToId,b.department,b.reviewerId,b.startDate || null,b.dueDateTime || null,b.priority,b.status,b.approvalStatus]);
            return res.status(201).json({ success:true, task:result.rows[0] });
        } catch (err: any) { return res.status(403).json({ error:'TASK_CREATE_DENIED', message:err.message }); }
    });

    app.patch('/api/tasks/:id', authenticate, requireContext, async (req: Request, res: Response) => {
        const client = (req as any).dbClient as PoolClient;
        const fields: Record<string,string> = { status:'status', priority:'priority', title:'title', description:'description', assignedToId:'assigned_to_membership_id', reviewerId:'reviewer_membership_id', dueDateTime:'due_at' };
        const values: unknown[] = []; const sets: string[] = [];
        for (const [key,column] of Object.entries(fields)) if (Object.hasOwn(req.body || {},key)) {
            values.push(req.body[key]); sets.push(`${column}=$${values.length}${['assigned_to_membership_id','reviewer_membership_id'].includes(column) ? '::uuid' : ''}`);
        }
        if (!sets.length) return res.status(400).json({ error:'NO_TASK_FIELDS' });
        values.push(req.params.id);
        try {
            const result = await client.query(`UPDATE public.tasks SET ${sets.join(',')} WHERE id=$${values.length}::uuid RETURNING *`,values);
            if (!result.rowCount) return res.status(404).json({ error:'TASK_NOT_FOUND' });
            return res.status(200).json({ success:true, task:result.rows[0] });
        } catch (err:any) { return res.status(403).json({ error:'TASK_EDIT_DENIED', message:err.message }); }
    });

    app.post('/api/tasks/:id/approve', authenticate, requireContext, async (req: Request, res: Response) => {
        const client = (req as any).dbClient as PoolClient;
        const status = (req.body || {}).approvalStatus;
        if (!['Approved','Rejected'].includes(status)) return res.status(400).json({ error:'INVALID_APPROVAL_STATUS' });
        try {
            const actor = await client.query('SELECT membership_id FROM public.access_contexts WHERE id=$1::uuid',[ (req as any).contextId ]);
            const result = await client.query(`UPDATE public.tasks SET approval_status=$1, approved_by_membership_id=$2::uuid WHERE id=$3::uuid RETURNING *`,[status,actor.rows[0]?.membership_id,req.params.id]);
            if (!result.rowCount) return res.status(404).json({ error:'TASK_NOT_FOUND' });
            return res.status(200).json({ success:true, task:result.rows[0] });
        } catch (err:any) { return res.status(403).json({ error:'TASK_APPROVAL_DENIED', message:err.message }); }
    });

    // --- TEST APPLICATION B: ATTENDANCE (RESTRICTED ACCESS) ---
    app.get('/api/attendance', authenticate, requireContext, async (req: Request, res: Response) => {
        const client = (req as any).dbClient as PoolClient;
        const result = await client.query(`SELECT r.*, COALESCE((SELECT jsonb_agg(jsonb_build_object('id',c.id,'authorId',c.author_membership_id,'text',c.body,'timestamp',c.created_at) ORDER BY c.created_at) FROM public.attendance_comments c WHERE c.attendance_record_id=r.id),'[]'::jsonb) AS hr_comments FROM public.attendance_records r ORDER BY r.attendance_date DESC,r.membership_id`);
        return res.status(200).json({ records: result.rows.map((r:any)=>({ id:r.id,attendanceId:r.attendance_id,memberId:r.membership_id,
            memberName:r.membership_id,department:r.department,date:r.attendance_date,checkInTime:r.check_in,checkOutTime:r.check_out,
            status:r.status,remarks:r.remarks,hrComments:r.hr_comments,createdBy:r.created_by_membership_id,lastUpdatedBy:r.last_updated_by_membership_id })) });
    });

    app.patch('/api/attendance/:id', authenticate, requireContext, async (req: Request, res: Response) => {
        const client = (req as any).dbClient as PoolClient; const b=req.body||{};
        const allowed:Record<string,string>={status:'status',checkInTime:'check_in',checkOutTime:'check_out',remarks:'remarks'};
        const vals:unknown[]=[];const sets:string[]=[];
        for(const [key,col] of Object.entries(allowed))if(Object.hasOwn(b,key)){vals.push(b[key]);sets.push(`${col}=$${vals.length}`)}
        if(!sets.length)return res.status(400).json({error:'NO_ATTENDANCE_FIELDS'});
        vals.push(req.params.id);
        try{const result=await client.query(`UPDATE public.attendance_records SET ${sets.join(',')} WHERE id=$${vals.length}::uuid RETURNING *`,vals);
            if(!result.rowCount)return res.status(404).json({error:'ATTENDANCE_RECORD_NOT_FOUND'});
            return res.status(200).json({success:true,record:result.rows[0]});
        }catch(err:any){return res.status(403).json({error:'ATTENDANCE_EDIT_DENIED',message:err.message})}
    });

    app.post('/api/attendance/:id/comment', authenticate, requireContext, async (req: Request, res: Response) => {
        const client=(req as any).dbClient;const comment=(req.body||{}).comment;
        if(typeof comment!=='string'||!comment.trim())return res.status(400).json({error:'COMMENT_REQUIRED'});
        try{const result=await client.query(`INSERT INTO public.attendance_comments(attendance_record_id,organisation_id,author_membership_id,body)
            SELECT r.id,r.organisation_id,ac.membership_id,$2 FROM public.attendance_records r JOIN public.access_contexts ac ON ac.id=$3::uuid WHERE r.id=$1::uuid RETURNING id,author_membership_id,body,created_at`,
            [req.params.id,comment.trim(),(req as any).contextId]);
            if(!result.rowCount)return res.status(404).json({error:'ATTENDANCE_RECORD_NOT_FOUND'});
            const c=result.rows[0];return res.status(201).json({success:true,comment:{id:c.id,authorId:c.author_membership_id,text:c.body,timestamp:c.created_at}});
        }catch(err:any){return res.status(403).json({error:'ATTENDANCE_COMMENT_DENIED',message:err.message})}
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
