const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const STATIC_DIR = '/var/www/static';

// VULN 1: fs.readdirSync with user-controlled directory - exposes arbitrary directory contents
router.get('/browse', (req, res) => {
    const subdir = req.query.dir || '';
    const target = path.join(STATIC_DIR, subdir);
    const entries = fs.readdirSync(target);
    res.json(entries);
});

// VULN 2: fs.readFileSync with template literal path - user controls name and type
router.get('/asset', (req, res) => {
    const name = req.query.name;
    const type = req.query.type;
    const filePath = `${STATIC_DIR}/${type}/${name}`;
    const content = fs.readFileSync(filePath);
    res.send(content);
});

// VULN 3: fs.copyFileSync with user-controlled destination - write to arbitrary path
router.post('/copy', (req, res) => {
    const { template, dest } = req.body;
    const src = path.join(STATIC_DIR, 'templates', template);
    fs.copyFileSync(src, dest);
    res.send('copied');
});

module.exports = router;
