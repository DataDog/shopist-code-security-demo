const express = require('express');
const jwt = require('jsonwebtoken');

const router = express.Router();

// VULN 1: Session cookie set with httpOnly: false - accessible to JavaScript (XSS exfiltration)
router.post('/auth/login', (req, res) => {
    const { username, password } = req.body;
    const user = authenticateUser(username, password);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const sessionToken = generateSessionToken(user.id);
    // httpOnly: false allows client-side JS to read the session cookie
    res.cookie('session', sessionToken, { httpOnly: false, maxAge: 86400000 });
    res.json({ message: 'Login successful', userId: user.id });
});

// VULN 2: Auth token cookie set with secure: false - transmitted over HTTP (cleartext)
router.post('/auth/remember-me', (req, res) => {
    const { username, password } = req.body;
    const user = authenticateUser(username, password);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const authToken = jwt.sign({ userId: user.id, role: user.role }, process.env.JWT_SECRET, {
        expiresIn: '30d',
    });
    // secure: false allows the auth cookie to be sent over unencrypted HTTP connections
    res.cookie('auth', authToken, { secure: false, httpOnly: true, maxAge: 2592000000 });
    res.json({ message: 'Remembered', userId: user.id });
});

// VULN 3: Remember-me cookie set with no flags at all - no httpOnly, no secure, no sameSite
router.post('/cart/persist', (req, res) => {
    const { userId, cartId } = req.body;
    // No cookie flags: vulnerable to XSS theft, network interception, and CSRF
    res.cookie('remember', userId);
    res.cookie('cart_id', cartId);
    res.json({ message: 'Cart and user persisted', userId, cartId });
});

function authenticateUser(username, password) { return { id: 1, role: 'user' }; }
function generateSessionToken(userId) { return 'tok_' + userId + '_' + Date.now(); }

module.exports = router;
