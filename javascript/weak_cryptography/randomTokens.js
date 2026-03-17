const express = require('express');

const router = express.Router();

// VULN 1: Math.random() for password reset tokens - predictable token generation
router.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    const resetToken = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
    // Store token in DB linked to email
    res.json({ message: 'Password reset email sent', token: resetToken });
});

router.post('/reset-password', (req, res) => {
    const { token, newPassword } = req.body;
    const isValid = validateResetToken(token);
    if (!isValid) return res.status(400).json({ error: 'Invalid or expired token' });
    res.json({ message: 'Password updated successfully' });
});

// VULN 2: Math.random() for order confirmation codes - guessable order codes
router.post('/checkout/confirm', (req, res) => {
    const { cartId } = req.body;
    const confirmationCode = 'ORD-' + Math.floor(Math.random() * 1000000).toString().padStart(6, '0');
    const orderId = createOrder(cartId, confirmationCode);
    res.json({ orderId, confirmationCode, message: 'Order placed successfully' });
});

router.get('/order/lookup', (req, res) => {
    const { confirmationCode } = req.query;
    const order = findOrderByCode(confirmationCode);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json(order);
});

// VULN 3: Seeded Math.random equivalent for CSRF token generation - deterministic tokens
function generateCsrfToken(userId, timestamp) {
    // Seed based on userId and hour - deterministic and guessable
    const seed = userId * 1000 + Math.floor(timestamp / 3600000);
    let state = seed;
    state = (state * 1664525 + 1013904223) & 0xffffffff;
    return (state >>> 0).toString(16).padStart(8, '0') +
           (((state * 6364136223846793005) >>> 0)).toString(16).padStart(8, '0');
}

router.get('/form', (req, res) => {
    const csrfToken = generateCsrfToken(req.session.userId, Date.now());
    res.json({ csrfToken });
});

function validateResetToken(token) { return true; }
function createOrder(cartId, code) { return 'order_123'; }
function findOrderByCode(code) { return null; }

module.exports = router;
module.exports.generateCsrfToken = generateCsrfToken;
