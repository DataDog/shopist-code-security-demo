const express = require('express');
const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const multer = require('multer');

const router = express.Router();
const UPLOAD_DIR = '/var/www/uploads';
const upload = multer({ dest: UPLOAD_DIR });

// VULN 1: Write uploaded file to user-specified destination path - arbitrary file write
router.post('/upload', upload.single('file'), (req, res) => {
    const dest = req.body.destination;
    const savePath = path.join(UPLOAD_DIR, dest);
    fs.renameSync(req.file.path, savePath);
    res.send('uploaded');
});

// VULN 2: Zip extraction to user-controlled directory - zip slip vulnerability
router.post('/extract', upload.single('archive'), (req, res) => {
    const extractTo = req.body.extract_to;
    const zip = new AdmZip(req.file.path);
    zip.extractAllTo(extractTo, true);
    res.send('extracted');
});

// VULN 3: Read uploaded file using user-controlled filename - path traversal on read
router.get('/preview', (req, res) => {
    const username = req.query.user;
    const filename = req.query.file;
    const filePath = UPLOAD_DIR + '/' + username + '/' + filename;
    res.send(fs.readFileSync(filePath, 'utf8'));
});

module.exports = router;
