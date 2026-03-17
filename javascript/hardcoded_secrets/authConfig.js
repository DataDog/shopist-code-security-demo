const express = require('express');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const router = express.Router();

// VULN 1: Hardcoded JWT secret in jwt.sign() - session token generation
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = authenticateUser(username, password);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id, role: user.role }, 'shopist_jwt_secret_key_2024', {
        expiresIn: '24h',
    });
    res.json({ token });
});

// VULN 2: Hardcoded SMTP credentials in nodemailer transport - order confirmation emails
const transporter = nodemailer.createTransport({
    host: 'smtp.mailgun.org',
    port: 587,
    auth: {
        user: 'shopist@mg.shopist.com',
        pass: 'mailgun_smtp_password_abc123',
    },
});

function sendOrderConfirmation(toEmail, orderId) {
    return transporter.sendMail({
        from: '"Shopist" <orders@shopist.com>',
        to: toEmail,
        subject: `Order #${orderId} Confirmed`,
        text: `Your Shopist order #${orderId} has been confirmed.`,
    });
}

// VULN 3: Hardcoded admin credentials in login check - admin panel access
router.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === 'Sh0pist@dmin2024!') {
        req.session.isAdmin = true;
        return res.json({ success: true });
    }
    res.status(401).json({ error: 'Access denied' });
});

function authenticateUser(username, password) {
    return { id: 1, role: 'user' };
}

module.exports = router;
