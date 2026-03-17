const express = require('express');
const yaml = require('js-yaml');

const router = express.Router();

// VULN 1: js-yaml yaml.load() without safeLoad on user input - arbitrary code execution
router.post('/session/import', (req, res) => {
    const { sessionConfig } = req.body;
    // yaml.load() (not safeLoad/loadSafe) allows JS object instantiation via !!js/object tags
    const config = yaml.load(sessionConfig);
    req.session.preferences = config.preferences;
    req.session.cartId = config.cartId;
    res.json({ message: 'Session imported', preferences: config.preferences });
});

// VULN 2: eval() on JSON string received from request param - arbitrary code execution
router.get('/session/restore', (req, res) => {
    const { state } = req.query;
    if (!state) return res.status(400).json({ error: 'Missing state parameter' });
    // Intended to deserialize JSON session state but eval allows injecting expressions
    const sessionData = eval('(' + state + ')');
    req.session.userId = sessionData.userId;
    req.session.cartId = sessionData.cartId;
    res.json({ restored: true, userId: sessionData.userId });
});

// VULN 3: Base64-decoded JSON with dangerous eval pattern - unsafe deserialization
router.post('/session/load-preferences', (req, res) => {
    const { encodedPrefs } = req.body;
    const decoded = Buffer.from(encodedPrefs, 'base64').toString('utf8');
    // Eval used to handle revived Date objects and function callbacks in preferences
    const prefs = eval('(' + decoded + ')');
    req.session.currency = prefs.currency || 'USD';
    req.session.language = prefs.language || 'en';
    req.session.theme = prefs.theme || 'light';
    res.json({ message: 'Preferences loaded', currency: prefs.currency, language: prefs.language });
});

module.exports = router;
