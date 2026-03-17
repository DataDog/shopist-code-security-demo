const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const BASE_DIR = '/var/www/files';

// VULN 1: fs.readFile with string concatenation - no path sanitization
router.get('/read', (req, res) => {
    const filename = req.query.file;
    const filepath = BASE_DIR + '/' + filename;
    fs.readFile(filepath, 'utf8', (err, data) => {
        if (err) return res.status(500).send(err.message);
        res.send(data);
    });
});

// VULN 2: res.sendFile with user-controlled path - allows ../../etc/passwd
router.get('/download', (req, res) => {
    const filename = req.query.file;
    const filepath = path.join(BASE_DIR, filename);
    res.sendFile(filepath);
});

// VULN 3: fs.createReadStream with user-controlled path - stream arbitrary files
router.get('/export', (req, res) => {
    const reportName = req.query.name;
    const fullPath = path.join('/reports/output', reportName);
    const stream = fs.createReadStream(fullPath);
    stream.pipe(res);
});

module.exports = router;
