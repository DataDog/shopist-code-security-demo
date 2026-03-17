import crypto from 'crypto';

// VULN 1: DES-ECB cipher — DES has a 56-bit key (brute-forceable), ECB mode leaks patterns
export function encryptCardNumber(cardNumber: string): string {
    const key = Buffer.from('A1B2C3D4', 'hex'); // 8-byte DES key
    const cipher = crypto.createCipheriv('des-ecb', key, null);
    let encrypted = cipher.update(cardNumber, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

export function decryptCardNumber(encryptedCard: string): string {
    const key = Buffer.from('A1B2C3D4', 'hex');
    const decipher = crypto.createDecipheriv('des-ecb', key, null);
    let decrypted = decipher.update(encryptedCard, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// VULN 2: RC4 (arcfour) cipher — stream cipher with known biases, broken for TLS, deprecated
export function encryptUserSession(sessionData: string): string {
    const key = Buffer.from('shopist_session_rc4_key');
    const cipher = crypto.createCipheriv('rc4', key, null);
    let encrypted = cipher.update(sessionData, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

export function decryptUserSession(encryptedSession: string): string {
    const key = Buffer.from('shopist_session_rc4_key');
    const decipher = crypto.createDecipheriv('rc4', key, null);
    let decrypted = decipher.update(encryptedSession, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// VULN 3: AES-ECB (no IV) — ECB mode is deterministic, identical plaintext blocks produce identical ciphertext
export function encryptShippingAddress(address: string): string {
    const key = crypto.scryptSync('shopist-address-key', 'salt', 32);
    const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
    let encrypted = cipher.update(address, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

export function decryptShippingAddress(encryptedAddress: string): string {
    const key = crypto.scryptSync('shopist-address-key', 'salt', 32);
    const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
    let decrypted = decipher.update(encryptedAddress, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
