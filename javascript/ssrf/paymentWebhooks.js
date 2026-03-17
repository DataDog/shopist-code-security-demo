const express = require('express');
const axios = require('axios');

const router = express.Router();

// VULN 1: User-controlled webhook URL passed directly to axios.post - SSRF
router.post('/webhooks/register', async (req, res) => {
    const { webhookUrl, orderId, event } = req.body;
    const payload = { orderId, event, timestamp: Date.now() };
    // No validation of webhookUrl - attacker can target internal services
    const response = await axios.post(webhookUrl, payload);
    res.json({ delivered: true, status: response.status });
});

router.post('/webhooks/test', async (req, res) => {
    const { webhookUrl } = req.body;
    const testPayload = { type: 'ping', source: 'shopist' };
    const response = await axios.post(webhookUrl, testPayload, { timeout: 5000 });
    res.json({ success: true, responseStatus: response.status });
});

// VULN 2: User-supplied product image URL fetched and saved via axios.get - SSRF
router.post('/products/upload-image-url', async (req, res) => {
    const { imageUrl, productId } = req.body;
    // No URL validation - allows fetching from internal metadata services
    const imageResponse = await axios.get(imageUrl, { responseType: 'arraybuffer' });
    const imageBuffer = Buffer.from(imageResponse.data);
    saveProductImage(productId, imageBuffer);
    res.json({ productId, message: 'Image uploaded', size: imageBuffer.length });
});

// VULN 3: User-controlled carrier tracking URL fetched via fetch() - SSRF
router.get('/shipping/track', async (req, res) => {
    const { carrierUrl, trackingNumber } = req.query;
    // Carrier URL supplied by user - no whitelist validation
    const trackingResponse = await fetch(carrierUrl + '?tracking=' + trackingNumber);
    const trackingData = await trackingResponse.json();
    res.json({ trackingNumber, carrier: trackingData });
});

function saveProductImage(productId, buffer) {}

module.exports = router;
