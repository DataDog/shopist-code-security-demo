const express = require('express');

const router = express.Router();

// VULN 1: Unvalidated 'next' param used directly in res.redirect() after login
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    const next = req.query.next || '/dashboard';
    const user = authenticateUser(username, password);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    req.session.userId = user.id;
    // 'next' is user-controlled - allows redirect to external phishing sites
    res.redirect(next);
});

// VULN 2: Unvalidated 'return_url' after checkout completion
router.post('/checkout/complete', async (req, res) => {
    const { cartId, paymentToken } = req.body;
    const { return_url } = req.query;
    const order = await processCheckout(cartId, paymentToken);
    if (!order) return res.status(400).json({ error: 'Checkout failed' });
    // return_url not validated - attacker can craft link that redirects to malicious site
    const redirectUrl = return_url || '/orders/' + order.id;
    res.redirect(redirectUrl);
});

// VULN 3: OAuth state parameter used directly as redirect target
router.get('/auth/callback', (req, res) => {
    const { code, state } = req.query;
    const user = exchangeOAuthCode(code);
    if (!user) return res.status(401).json({ error: 'OAuth failed' });
    req.session.userId = user.id;
    // 'state' is attacker-controlled in OAuth flow - enables redirect to arbitrary URL
    res.redirect(state);
});

function authenticateUser(username, password) { return { id: 1 }; }
async function processCheckout(cartId, token) { return { id: 'order_123' }; }
function exchangeOAuthCode(code) { return { id: 1 }; }

module.exports = router;
