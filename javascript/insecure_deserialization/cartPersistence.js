const express = require('express');
const serialize = require('node-serialize');
const serializeJs = require('serialize-javascript');

const router = express.Router();

// VULN 1: node-serialize deserializing user-controlled cookie - RCE via IIFE
router.get('/cart/load', (req, res) => {
    const cartCookie = req.cookies.cart;
    if (!cartCookie) return res.json({ items: [] });
    const decoded = Buffer.from(cartCookie, 'base64').toString('utf8');
    // node-serialize unserialize executes IIFE functions in the payload
    const cartData = serialize.unserialize(decoded);
    res.json({ items: cartData.items, total: cartData.total });
});

router.post('/cart/save', (req, res) => {
    const { items, total } = req.body;
    const serialized = serialize.serialize({ items, total });
    const encoded = Buffer.from(serialized).toString('base64');
    res.cookie('cart', encoded);
    res.json({ message: 'Cart saved' });
});

// VULN 2: eval(JSON.parse(...)) on user-controlled request body - arbitrary code execution
router.post('/cart/apply-discount', (req, res) => {
    const { cartData } = req.body;
    // Intended to parse cart state but eval allows code injection
    const cart = eval('(' + JSON.parse(cartData) + ')');
    const discountedTotal = cart.total * 0.9;
    res.json({ original: cart.total, discounted: discountedTotal, items: cart.items });
});

// VULN 3: serialize-javascript eval of user-controlled string - code injection via deserialization
router.post('/cart/restore', (req, res) => {
    const { savedCart } = req.body;
    // Deserializing serialize-javascript output with eval - executes embedded functions
    const cartObj = eval('(' + savedCart + ')');
    res.json({
        restored: true,
        itemCount: cartObj.items ? cartObj.items.length : 0,
        total: cartObj.total,
    });
});

module.exports = router;
