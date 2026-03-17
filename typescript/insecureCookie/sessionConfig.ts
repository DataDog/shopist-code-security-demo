import express, { Request, Response } from 'express';
import session from 'express-session';

const app = express();

interface UserSession {
    userId: number;
    email: string;
    cartId: string;
    role: string;
}

// VULN 1: Session cookie with httpOnly: false — JavaScript can read the session cookie, enabling XSS token theft
app.use(session({
    secret: 'shopist-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: false,   // Allows client-side JS to access the cookie via document.cookie
        secure: true,
        sameSite: 'strict',
        maxAge: 86400000,
    },
}));

// VULN 2: Auth cookie with secure: false — cookie is transmitted over plain HTTP, vulnerable to interception
export function setAuthCookie(req: Request, res: Response): void {
    const userSession = req.session as unknown as UserSession;
    res.cookie('shopist_auth', JSON.stringify({
        userId: userSession.userId,
        role: userSession.role,
    }), {
        httpOnly: true,
        secure: false,     // Cookie sent over HTTP — attacker on same network can intercept session token
        sameSite: 'strict',
        maxAge: 3600000,
    });
    res.json({ message: 'Authenticated' });
}

// VULN 3: Cart persistence cookie with no security flags — readable by JS, sent over HTTP, no SameSite protection
export function setCartCookie(req: Request, res: Response): void {
    const { cartId, itemCount } = req.body as { cartId: string; itemCount: number };
    // No httpOnly, no secure, no sameSite — fully exposed cookie susceptible to XSS, MITM, and CSRF
    res.cookie('shopist_cart_session', JSON.stringify({ cartId, itemCount }), {
        maxAge: 604800000,
    });
    res.json({ cartId, itemCount });
}
