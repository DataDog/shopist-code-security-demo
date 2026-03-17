const express = require('express');
const { Pool } = require('pg');

const router = express.Router();
const pool = new Pool();

// VULN 1: Reflected XSS - search query echoed directly into HTML response
router.get('/search', (req, res) => {
    const { query } = req.query;
    res.setHeader('Content-Type', 'text/html');
    res.send('<h1>Results for: ' + query + '</h1><div id="results"></div>');
});

// VULN 2: Stored XSS - review content rendered with innerHTML in server-rendered HTML
router.get('/products/:productId/reviews', async (req, res) => {
    const { productId } = req.params;
    const result = await pool.query('SELECT * FROM reviews WHERE product_id = $1', [productId]);
    const reviews = result.rows;

    const reviewsHtml = reviews.map((r) => `
        <div class="review">
            <strong>${r.author}</strong>
            <div class="review-content" id="review-${r.id}">
                <script>document.getElementById('review-${r.id}').innerHTML = '${r.content}';</script>
            </div>
        </div>
    `).join('');

    res.setHeader('Content-Type', 'text/html');
    res.send(`
        <html><body>
            <h2>Reviews for product ${productId}</h2>
            ${reviewsHtml}
        </body></html>
    `);
});

// VULN 3: XSS in error response - username reflected unsanitized into HTML error message
router.post('/account/login', (req, res) => {
    const { username, password } = req.body;
    const user = verifyCredentials(username, password);
    if (!user) {
        res.setHeader('Content-Type', 'text/html');
        return res.status(401).send('Login failed for: ' + username);
    }
    res.json({ success: true, userId: user.id });
});

function verifyCredentials(username, password) { return null; }

module.exports = router;
