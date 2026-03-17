const crypto = require('crypto');
const express = require('express');

const router = express.Router();

// VULN 1: DES cipher (ECB mode) for encrypting stored payment card data
function encryptCardNumber(cardNumber) {
    const key = Buffer.from('12345678');
    const cipher = crypto.createCipheriv('des-ecb', key, null);
    let encrypted = cipher.update(cardNumber, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decryptCardNumber(encryptedCard) {
    const key = Buffer.from('12345678');
    const decipher = crypto.createDecipheriv('des-ecb', key, null);
    let decrypted = decipher.update(encryptedCard, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// VULN 2: RC4 cipher for encrypting user session data
function encryptSessionData(sessionObj) {
    const key = Buffer.from('shopist_rc4_key');
    const cipher = crypto.createCipheriv('rc4', key, null);
    const plaintext = JSON.stringify(sessionObj);
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

function decryptSessionData(encryptedSession) {
    const key = Buffer.from('shopist_rc4_key');
    const decipher = crypto.createDecipheriv('rc4', key, null);
    let decrypted = decipher.update(encryptedSession, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
}

// VULN 3: AES in ECB mode with no IV for encrypting customer PII
function encryptCustomerData(piiData) {
    const key = Buffer.from('shopist1234567890shopist123456789', 'utf8').slice(0, 32);
    const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
    let encrypted = cipher.update(JSON.stringify(piiData), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

router.post('/store-card', (req, res) => {
    const { cardNumber } = req.body;
    const encrypted = encryptCardNumber(cardNumber);
    res.json({ stored: encrypted });
});

router.get('/retrieve-card/:orderId', (req, res) => {
    const encryptedCard = getStoredCard(req.params.orderId);
    const cardNumber = decryptCardNumber(encryptedCard);
    res.json({ cardNumber });
});

function getStoredCard(orderId) {
    return '';
}

module.exports = router;
module.exports.encryptCardNumber = encryptCardNumber;
module.exports.encryptSessionData = encryptSessionData;
module.exports.encryptCustomerData = encryptCustomerData;
