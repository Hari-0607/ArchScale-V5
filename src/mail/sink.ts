import crypto from 'crypto';

export interface SentMail {
    to: string;
    subject: string;
    rawToken: string;
    invitationId?: string;
    inviteUrl: string;
    body: string;
    sentAt: Date;
}

const sentMails: SentMail[] = [];

export interface SendInvitationOptions {
    to: string;
    rawToken: string;
    invitationId?: string;
    organisationName?: string;
}

export async function sendInvitationMail(options: SendInvitationOptions): Promise<{ success: boolean; messageId: string; inviteUrl: string }> {
    const isStaging = process.env.ARCHSCALE_STAGING_TESTS === 'true' || !!process.env.SUPABASE_URL;
    const baseUrl = process.env.ARCHSCALE_FRONTEND_URL || 'http://127.0.0.1:3000';
    // B0.5: Token in URL fragment (#token=...), not query string (?token=...)
    const inviteUrl = `${baseUrl}/accept#token=${options.rawToken}`;
    const orgName = options.organisationName || 'ArchScale';
    const body = `You have been invited to join ${orgName}.\n\nAccept your invitation by visiting:\n${inviteUrl}\n\nThis invitation link contains your secret token in the URL fragment.`;

    if (isStaging && process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
        try {
            const { createClient } = await import('@supabase/supabase-js');
            const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
                auth: { persistSession: false, autoRefreshToken: false }
            });
            const { data, error } = await supabase.auth.admin.inviteUserByEmail(options.to, {
                redirectTo: inviteUrl,
                data: {
                    invitation_id: options.invitationId,
                    raw_token: options.rawToken,
                    invite_url: inviteUrl
                }
            });
            if (error) {
                console.error('[MailSink:Staging] Failed to send invite via Supabase:', error.message);
                throw error;
            }
            return { success: true, messageId: data?.user?.id || 'supabase-invite', inviteUrl };
        } catch (err: any) {
            console.error('[MailSink:Staging] Supabase invite error:', err.message);
            throw err;
        }
    }

    // Local in-memory sink
    sentMails.push({
        to: options.to,
        subject: `You have been invited to join ${orgName}`,
        rawToken: options.rawToken,
        invitationId: options.invitationId,
        inviteUrl,
        body,
        sentAt: new Date()
    });

    return {
        success: true,
        messageId: `sink-${crypto.randomBytes(8).toString('hex')}`,
        inviteUrl
    };
}

export function getSentMails(): readonly SentMail[] {
    return sentMails;
}

export function clearSentMails(): void {
    sentMails.length = 0;
}

