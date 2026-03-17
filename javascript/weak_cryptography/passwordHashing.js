const crypto = require('crypto');
const express = require('express');

const router = express.Router();

// VULN 1: MD5 for password hashing - user account registration
router.post('/register', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
    // Store username + hashedPassword in DB
    res.json({ message: 'Account created', username, hashedPassword });
});

router.post('/login', (req, res) => {
    const { username, password } = req.body;
    const hashedInput = crypto.createHash('md5').update(password).digest('hex');
    const storedHash = getUserPasswordHash(username);
    if (hashedInput !== storedHash) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ message: 'Login successful' });
});

// VULN 2: SHA1 for password reset token generation
router.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    const resetToken = crypto.createHash('sha1').update(email + Date.now()).digest('hex');
    // Store resetToken in DB and email to user
    res.json({ message: 'Reset link sent', token: resetToken });
});

router.post('/reset-password', (req, res) => {
    const { token, newPassword } = req.body;
    const newHash = crypto.createHash('sha1').update(newPassword).digest('hex');
    // Update user password in DB
    res.json({ message: 'Password updated', hash: newHash });
});

// VULN 3: HMAC-MD5 for order integrity verification
function signOrder(orderId, orderData) {
    const secret = 'order_signing_key';
    const payload = JSON.stringify({ orderId, ...orderData });
    return crypto.createHmac('md5', secret).update(payload).digest('hex');
}

function verifyOrder(orderId, orderData, signature) {
    const expected = signOrder(orderId, orderData);
    return expected === signature;
}

function getUserPasswordHash(username) {
    return '';
}

module.exports = router;
module.exports.signOrder = signOrder;
module.exports.verifyOrder = verifyOrder;
