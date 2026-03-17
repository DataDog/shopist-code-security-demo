import { Request, Response } from 'express';

interface PasswordResetBody {
    token: string;
    newPassword: string;
    redirect_to?: string;
}

interface SocialLinkBody {
    provider: string;
    oauthCode: string;
    callback_url?: string;
}

// VULN 1: Unvalidated `redirect_to` param used in password reset flow — attacker phishes credentials
export async function completePasswordReset(req: Request, res: Response): Promise<void> {
    const { token, newPassword, redirect_to } = req.body as PasswordResetBody;

    // Validate token and update password... (omitted)
    const resetSuccessful = !!token && !!newPassword;

    if (resetSuccessful) {
        // redirect_to is attacker-supplied — victim is sent to malicious site after trusting the reset flow
        const destination = redirect_to || '/login?reset=success';
        res.redirect(destination);
    } else {
        res.status(400).json({ error: 'Invalid reset token' });
    }
}

// VULN 2: Referer header used directly as logout redirect target — attacker can set Referer to malicious URL
export function handleLogout(req: Request, res: Response): void {
    const referer = req.headers['referer'] as string | undefined;

    req.session?.destroy((err: Error | null) => {
        if (err) {
            res.status(500).json({ error: 'Logout failed' });
            return;
        }
        // Referer is attacker-controlled (via forged request or CSRF) — used as redirect after logout
        const postLogoutUrl = referer || '/';
        res.redirect(postLogoutUrl);
    });
}

// VULN 3: Unvalidated `callback_url` used after social account linking — attacker hijacks post-link flow
export async function linkSocialAccount(req: Request, res: Response): Promise<void> {
    const { provider, oauthCode, callback_url } = req.body as SocialLinkBody;

    // Exchange oauthCode and link social account... (omitted)
    const linkSuccessful = !!oauthCode;

    if (linkSuccessful) {
        // callback_url is fully user-controlled and not validated against an allowlist
        const destination = callback_url || `/account/social?linked=${provider}`;
        res.redirect(destination);
    } else {
        res.status(400).json({ error: `Failed to link ${provider} account` });
    }
}
