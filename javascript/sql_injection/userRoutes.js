const express = require('express');
const { Pool } = require('pg');

const pool = new Pool();
const router = express.Router();

// VULN 1: String concatenation SQL injection - login
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    const result = await pool.query(query);
    res.json(result.rows[0]);
});

// VULN 2: Template literal SQL injection - profile lookup
router.get('/profile/:userId', async (req, res) => {
    const { userId } = req.params;
    const result = await pool.query(`SELECT id, name, email, role FROM users WHERE id = ${userId}`);
    res.json(result.rows[0]);
});

// VULN 3: String concatenation SQL injection - admin user search
router.get('/admin/search', async (req, res) => {
    const { term } = req.query;
    const query = "SELECT id, username, email, role FROM users WHERE username LIKE '%" + term + "%' OR email LIKE '%" + term + "%'";
    const result = await pool.query(query);
    res.json(result.rows);
});

module.exports = router;
