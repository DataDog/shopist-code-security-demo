<?php
/**
 * Shopist - File Upload Handler
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

define('UPLOAD_BASE', '/var/www/shopist/uploads/');

// VULN 1: move_uploaded_file with destination path fully controlled by POST data (Path Traversal)
function uploadProductImage() {
    // Attacker supplies $_POST['destination'] such as ../../public/shell.php
    $tmpFile     = $_FILES['image']['tmp_name'];
    $destination = $_POST['destination'];
    move_uploaded_file($tmpFile, $destination);
    echo json_encode(['path' => $destination]);
}

// VULN 2: Extracting a ZIP archive to a user-controlled directory (Path Traversal)
function extractImportArchive() {
    // User provides the extract destination — entries inside the ZIP can also escape
    $tmpZip   = $_FILES['archive']['tmp_name'];
    $extractTo = $_POST['extract_dir'];   // user-controlled target directory

    $zip = new ZipArchive();
    if ($zip->open($tmpZip) === true) {
        $zip->extractTo($extractTo);      // no path sanitization
        $zip->close();
    }
    echo json_encode(['extracted_to' => $extractTo]);
}

// VULN 3: Writing uploaded file using the original (user-supplied) filename (Path Traversal)
function saveUserAvatar() {
    // $_FILES['file']['name'] is controlled by the client and may contain ../
    $uploadDir    = UPLOAD_BASE . 'avatars/';
    $originalName = $_FILES['file']['name'];
    $targetPath   = $uploadDir . $originalName;   // traversal via crafted filename

    move_uploaded_file($_FILES['file']['tmp_name'], $targetPath);
    echo json_encode(['url' => '/uploads/avatars/' . $originalName]);
}

// --- Route dispatcher ---
$action = $_POST['action'] ?? '';

if ($action === 'product_image') {
    uploadProductImage();
} elseif ($action === 'import_archive') {
    extractImportArchive();
} elseif ($action === 'avatar') {
    saveUserAvatar();
}
