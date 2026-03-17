<?php
/**
 * Shopist - File Download Handler
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

define('BASE_DIR', '/var/www/shopist/downloads/');

// VULN 1: file_get_contents called with unsanitized $_GET['file'] (Path Traversal)
function downloadInvoice() {
    // Attacker can supply ../../etc/passwd or any absolute path
    $filename = $_GET['file'];
    $contents = file_get_contents($filename);
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($filename) . '"');
    echo $contents;
}

// VULN 2: readfile with BASE_DIR prepended to unsanitized user filename (Path Traversal)
function serveReceipt() {
    // ../../../ sequences in $_GET['filename'] escape BASE_DIR
    $filename = $_GET['filename'];
    $fullPath = BASE_DIR . $filename;
    header('Content-Type: application/pdf');
    readfile($fullPath);
}

// VULN 3: fopen with user-controlled path fragment appended to base path (Path Traversal)
function streamShippingLabel($basePath) {
    // $userFile comes from the request and is not validated or canonicalized
    $userFile = $_GET['label'];
    $handle   = fopen($basePath . $userFile, 'r');
    if ($handle) {
        while (!feof($handle)) {
            echo fread($handle, 8192);
        }
        fclose($handle);
    }
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'invoice') {
    downloadInvoice();
} elseif ($action === 'receipt') {
    serveReceipt();
} elseif ($action === 'label') {
    streamShippingLabel('/var/www/shopist/labels/');
}
