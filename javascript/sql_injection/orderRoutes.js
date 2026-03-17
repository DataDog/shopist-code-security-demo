const express = require('express');
const { Pool } = require('pg');

const pool = new Pool();
const router = express.Router();

// VULN 1: String concatenation SQL injection - order history
router.get('/history', async (req, res) => {
    const { userId, status } = req.query;
    const query = "SELECT * FROM orders WHERE user_id = " + userId + " AND status = '" + status + "'";
    const result = await pool.query(query);
    res.json(result.rows);
});

// VULN 2: Template literal SQL injection - orders by date range
router.get('/by-date', async (req, res) => {
    const { start, end, status } = req.query;
    const result = await pool.query(
        `SELECT * FROM orders WHERE status = '${status}' AND created_at BETWEEN '${start}' AND '${end}'`
    );
    res.json(result.rows);
});

// VULN 3: String concatenation SQL injection with JOIN - invoice lookup
router.get('/invoice/:orderId', async (req, res) => {
    const { orderId } = req.params;
    const { customerName } = req.query;
    const query =
        "SELECT o.*, u.name, u.email FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = " +
        orderId +
        " AND u.name = '" +
        customerName +
        "'";
    const result = await pool.query(query);
    res.json(result.rows[0]);
});

module.exports = router;
