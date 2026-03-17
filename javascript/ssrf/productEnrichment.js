const express = require('express');
const http = require('http');
const axios = require('axios');

const router = express.Router();

// VULN 1: User-supplied source URL fetched via http.get() - SSRF
router.post('/products/import', (req, res) => {
    const { sourceUrl, categoryId } = req.body;
    // No URL validation - allows requests to internal network
    http.get(sourceUrl, (response) => {
        let data = '';
        response.on('data', (chunk) => { data += chunk; });
        response.on('end', () => {
            const products = JSON.parse(data);
            importProducts(categoryId, products);
            res.json({ imported: products.length, category: categoryId });
        });
    }).on('error', (err) => {
        res.status(500).json({ error: err.message });
    });
});

// VULN 2: User-supplied RSS feed URL fetched via axios.get() for blog/promotions - SSRF
router.post('/promotions/sync-feed', async (req, res) => {
    const { feedUrl, storeId } = req.body;
    // Allows attacker to make server request internal metadata at http://169.254.169.254
    const feedResponse = await axios.get(feedUrl, {
        headers: { 'Accept': 'application/rss+xml, application/xml' },
    });
    const feedContent = feedResponse.data;
    const promotions = parseFeed(feedContent);
    res.json({ storeId, syncedPromotions: promotions.length });
});

// VULN 3: User-controlled API base URL concatenated with path then fetched - SSRF
router.get('/products/enrich', async (req, res) => {
    const { apiBase, productId } = req.query;
    // apiBase is user-controlled - attacker can target internal services with path appended
    const enrichmentUrl = apiBase + '/products/' + productId;
    const enrichResponse = await axios.get(enrichmentUrl);
    res.json({ productId, enrichment: enrichResponse.data });
});

function importProducts(categoryId, products) {}
function parseFeed(content) { return []; }

module.exports = router;
