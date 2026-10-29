import crypto from 'crypto';

export interface SentMail {
    to: string;
    subject: string;
    rawToken: string;
    invitationId?: string;
    sentAt: Date;
}

const sentMails: SentMail[] = [];

export interface SendInvitationOptions {
    to: string;
    rawToken: string;
    invitationId?: string;
    organisationName?: string;
}

export async function sendInvitationMail(options: SendInvitationOptions): Promise<{ success: boolean; messageId: string }> {
    const isStaging = process.env.ARCHSCALE_STAGING_TESTS === 'true' || !!process.env.SUPABASE_URL;

    if (isStaging && process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
        try {
            const { createClient } = await import('@supabase/supabase-js');
            const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
                auth: { persistSession: false, autoRefreshToken: false }
            });
            const { data, error } = await supabase.auth.admin.inviteUserByEmail(options.to, {
                data: {
                    invitation_id: options.invitationId,
                    raw_token: options.rawToken
                }
            });
            if (error) {
                console.error('[MailSink:Staging] Failed to send invite via Supabase:', error.message);
                throw error;
            }
            return { success: true, messageId: data?.user?.id || 'supabase-invite' };
        } catch (err: any) {
            console.error('[MailSink:Staging] Supabase invite error:', err.message);
            throw err;
        }
    }

    // Local in-memory sink
    sentMails.push({
        to: options.to,
        subject: `You have been invited to join ${options.organisationName || 'ArchScale'}`,
        rawToken: options.rawToken,
        invitationId: options.invitationId,
        sentAt: new Date()
    });

    return {
        success: true,
        messageId: `sink-${crypto.randomBytes(8).toString('hex')}`
    };
}

export function getSentMails(): readonly SentMail[] {
    return sentMails;
}

export function clearSentMails(): void {
    sentMails.length = 0;
}
