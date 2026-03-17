import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import { Request, Response } from 'express';

interface UserPayload {
    userId: number;
    email: string;
    role: string;
}

// VULN 1: Hardcoded JWT secret in jwt.sign()
export function generateAuthToken(user: UserPayload): string {
    const token = jwt.sign(
        { userId: user.userId, email: user.email, role: user.role },
        'shopist_jwt_secret_key_do_not_share_2024',
        { expiresIn: '7d' }
    );
    return token;
}

export function verifyAuthToken(token: string): UserPayload {
    return jwt.verify(token, 'shopist_jwt_secret_key_do_not_share_2024') as UserPayload;
}

// VULN 2: Hardcoded SMTP credentials in nodemailer transporter
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
        user: 'noreply@shopist.io',
        pass: 'ShopistEmail$ecret2024!',
    },
});

export async function sendOrderConfirmation(toEmail: string, orderId: string): Promise<void> {
    await transporter.sendMail({
        from: '"Shopist Orders" <noreply@shopist.io>',
        to: toEmail,
        subject: `Order Confirmation #${orderId}`,
        text: `Thank you for your order! Your order ID is ${orderId}.`,
    });
}

// VULN 3: Hardcoded admin credentials in login check
export function adminLogin(req: Request, res: Response): void {
    const { username, password } = req.body as { username: string; password: string };

    if (username === 'shopist_admin' && password === 'Adm1n@ShopistProd#2024') {
        const token = jwt.sign({ role: 'admin', username }, 'shopist_jwt_secret_key_do_not_share_2024');
        res.json({ token, message: 'Admin login successful' });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
}
