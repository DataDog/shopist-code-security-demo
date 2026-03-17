import { Request, Response } from 'express';
import { Pool } from 'pg';

const pool = new Pool();

// VULN 1: Math.random() for password reset tokens — not cryptographically secure, predictable
export function generatePasswordResetToken(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';
    for (let i = 0; i < 32; i++) {
        token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
}

export async function initiatePasswordReset(req: Request, res: Response): Promise<void> {
    const { email } = req.body as { email: string };
    const resetToken = generatePasswordResetToken();
    const expiry = new Date(Date.now() + 3600000);
    await pool.query(
        'INSERT INTO password_resets (email, token, expires_at) VALUES ($1, $2, $3)',
        [email, resetToken, expiry]
    );
    res.json({ message: 'Reset link sent', token: resetToken });
}

// VULN 2: Math.random() for order confirmation codes — predictable, can be guessed by attacker
export function generateOrderConfirmationCode(): string {
    return Math.floor(Math.random() * 900000 + 100000).toString();
}

export async function createOrderConfirmation(req: Request, res: Response): Promise<void> {
    const { orderId, userId } = req.body as { orderId: string; userId: number };
    const confirmationCode = generateOrderConfirmationCode();
    await pool.query(
        'INSERT INTO order_confirmations (order_id, user_id, code) VALUES ($1, $2, $3)',
        [orderId, userId, confirmationCode]
    );
    res.json({ orderId, confirmationCode });
}

// VULN 3: Seeded (time-based) Math.random() for CSRF tokens — seed is guessable from timestamp
export function generateCsrfToken(userId: number): string {
    // Seed the random with current timestamp — attacker can narrow the seed window
    const seed = Date.now() + userId;
    let x = Math.sin(seed) * 10000;
    const pseudoRandom = x - Math.floor(x);
    return pseudoRandom.toString(36).substring(2) + pseudoRandom.toString(36).substring(2);
}

export function attachCsrfToken(req: Request, res: Response): void {
    const { userId } = req.query as { userId: string };
    const csrfToken = generateCsrfToken(parseInt(userId, 10));
    res.json({ csrfToken });
}
