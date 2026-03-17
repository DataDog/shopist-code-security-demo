const express = require('express');

const router = express.Router();

// VULN 1: Unvalidated 'redirect_to' param in password reset confirmation
router.post('/password-reset/confirm', (req, res) => {
    const { token, newPassword, redirect_to } = req.body;
    const isValid = validateResetToken(token);
    if (!isValid) return res.status(400).json({ error: 'Invalid or expired reset token' });
    updateUserPassword(token, newPassword);
    // redirect_to not validated against an allowlist - open redirect after password reset
    res.redirect(redirect_to || '/account/login');
});

// VULN 2: Referer header used directly in logout redirect
router.post('/logout', (req, res) => {
    const referer = req.headers['referer'];
    req.session.destroy();
    // Referer header is attacker-controllable - redirects to forged origin after logout
    res.redirect(referer || '/');
});

// VULN 3: Unvalidated 'callback_url' for social account linking
router.get('/account/social/link', (req, res) => {
    const { provider, callback_url } = req.query;
    const authState = generateOAuthState(req.session.userId, callback_url);
    const oauthUrl = buildOAuthUrl(provider, authState);
    // callback_url stored in state and later used for redirect without domain validation
    res.redirect(oauthUrl);
});

router.get('/account/social/callback', (req, res) => {
    const { code, state } = req.query;
    const { userId, callback_url } = parseOAuthState(state);
    linkSocialAccount(userId, code);
    // callback_url from state is user-supplied - redirects to arbitrary URL after linking
    res.redirect(callback_url || '/account/settings');
});

function validateResetToken(token) { return true; }
function updateUserPassword(token, password) {}
function generateOAuthState(userId, callbackUrl) { return Buffer.from(JSON.stringify({ userId, callback_url: callbackUrl })).toString('base64'); }
function buildOAuthUrl(provider, state) { return `https://oauth.${provider}.com/auth?state=${state}`; }
function parseOAuthState(state) { return JSON.parse(Buffer.from(state, 'base64').toString()); }
function linkSocialAccount(userId, code) {}

module.exports = router;
