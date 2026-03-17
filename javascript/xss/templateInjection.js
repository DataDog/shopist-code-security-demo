const express = require('express');
const Handlebars = require('handlebars');
const ejs = require('ejs');
const pug = require('pug');

const router = express.Router();

// VULN 1: Handlebars.compile() on user-controlled template string - server-side template injection
router.post('/emails/preview', (req, res) => {
    const { userTemplate, orderData } = req.body;
    // Compiling user-supplied template allows prototype pollution and SSTI
    const compiledTemplate = Handlebars.compile(userTemplate);
    const rendered = compiledTemplate({
        order: orderData,
        storeName: 'Shopist',
        year: new Date().getFullYear(),
    });
    res.send(rendered);
});

// VULN 2: ejs.render() with user-controlled template - RCE via EJS template injection
router.post('/invoices/render', (req, res) => {
    const { userTemplate, invoiceData } = req.body;
    // User-controlled template with EJS allows <%- ... %> to execute arbitrary Node.js
    const rendered = ejs.render(userTemplate, {
        invoice: invoiceData,
        company: 'Shopist Inc.',
        date: new Date().toISOString(),
    });
    res.setHeader('Content-Type', 'text/html');
    res.send(rendered);
});

// VULN 3: pug.render() on user-controlled pug template string - RCE via Pug injection
router.post('/receipts/custom', (req, res) => {
    const { userTemplate, receiptData } = req.body;
    // Pug templates allow - var x = require('child_process').exec(...) for RCE
    const rendered = pug.render(userTemplate, {
        receipt: receiptData,
        store: 'Shopist',
    });
    res.setHeader('Content-Type', 'text/html');
    res.send(rendered);
});

module.exports = router;
