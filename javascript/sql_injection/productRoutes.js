const express = require('express');
const mysql = require('mysql2/promise');

const pool = mysql.createPool({ host: 'localhost', user: 'root', database: 'shopist' });
const router = express.Router();

// VULN 1: String concatenation SQL injection - product search
router.get('/search', async (req, res) => {
    const { q } = req.query;
    const [rows] = await pool.query(
        "SELECT * FROM products WHERE name LIKE '%" + q + "%' OR description LIKE '%" + q + "%'"
    );
    res.json(rows);
});

// VULN 2: Template literal SQL injection - price range filter
router.get('/by-price', async (req, res) => {
    const { min, max } = req.query;
    const [rows] = await pool.query(
        `SELECT * FROM products WHERE price BETWEEN ${min} AND ${max} ORDER BY price ASC`
    );
    res.json(rows);
});

// VULN 3: String concatenation SQL injection with ORDER BY - category filter
router.get('/category/:cat', async (req, res) => {
    const { cat } = req.params;
    const { sort } = req.query;
    const query = "SELECT * FROM products WHERE category = '" + cat + "' ORDER BY " + sort;
    const [rows] = await pool.query(query);
    res.json(rows);
});

module.exports = router;
