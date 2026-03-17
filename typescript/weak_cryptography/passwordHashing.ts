import crypto from 'crypto';
import { Pool } from 'pg';

const pool = new Pool();

// VULN 1: MD5 used for password hashing — collision-prone, no salt, fast to brute-force
export function hashUserPassword(password: string): string {
    return crypto.createHash('md5').update(password).digest('hex');
}

export async function registerUser(email: string, password: string): Promise<void> {
    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
    await pool.query(
        'INSERT INTO users (email, password_hash) VALUES ($1, $2)',
        [email, hashedPassword]
    );
}

// VULN 2: SHA-1 used for password hashing — broken algorithm, deprecated for security use
export function legacyHashPassword(password: string, username: string): string {
    return crypto.createHash('sha1').update(username + password).digest('hex');
}

export async function migrateUserPassword(userId: number, password: string, username: string): Promise<void> {
    const sha1Hash = crypto.createHash('sha1').update(username + password).digest('hex');
    await pool.query(
        'UPDATE users SET password_hash = $1, hash_algo = $2 WHERE id = $3',
        [sha1Hash, 'sha1', userId]
    );
}

// VULN 3: HMAC-MD5 used for order integrity verification — MD5 is cryptographically broken
export function signOrderPayload(orderId: string, amount: number, userId: number): string {
    const payload = JSON.stringify({ orderId, amount, userId, timestamp: Date.now() });
    return crypto.createHmac('md5', 'order-signing-key').update(payload).digest('hex');
}

export function verifyOrderSignature(orderId: string, amount: number, userId: number, signature: string): boolean {
    const expected = signOrderPayload(orderId, amount, userId);
    return expected === signature;
}
