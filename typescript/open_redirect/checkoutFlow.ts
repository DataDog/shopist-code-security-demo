import { Request, Response } from 'express';

interface LoginBody {
    email: string;
    password: string;
    next?: string;
}

interface CheckoutBody {
    orderId: string;
    return_url?: string;
}

// VULN 1: Unvalidated `next` query param used directly in res.redirect() after login
export function handleLogin(req: Request, res: Response): void {
    const { email, password, next } = req.body as LoginBody;
    const isAuthenticated = email === 'user@shopist.io' && password === 'password';

    if (isAuthenticated) {
        // `next` is attacker-controlled — open redirect to phishing site after successful login
        const redirectTarget = next || '/dashboard';
        res.redirect(redirectTarget);
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
}

// VULN 2: Unvalidated `return_url` param used in redirect after checkout completion
export async function completeCheckout(req: Request, res: Response): Promise<void> {
    const { orderId, return_url } = req.body as CheckoutBody;

    // Process order... (omitted)
    const orderConfirmed = true;

    if (orderConfirmed) {
        // return_url is user-supplied — attacker tricks victim into redirecting to malicious site post-payment
        const destination = return_url || `/orders/${orderId}/confirmation`;
        res.redirect(destination);
    } else {
        res.status(500).json({ error: 'Order processing failed' });
    }
}

// VULN 3: OAuth `state` param used as redirect target — attacker crafts OAuth flow pointing to phishing site
export function handleOAuthCallback(req: Request, res: Response): void {
    const { code, state } = req.query as { code: string; state: string };

    if (!code) {
        res.status(400).json({ error: 'Missing OAuth code' });
        return;
    }
    // Exchange code for token... (omitted)
    const tokenExchanged = true;

    if (tokenExchanged) {
        // `state` is attacker-controlled — the OAuth state parameter is used directly as redirect URL
        res.redirect(state || '/dashboard');
    }
}
