<?php
/**
 * Shopist - File Operation Utilities
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// VULN 1: system() called with unsanitized user input for image conversion (Command Injection)
function convertProductImage() {
    // $_GET['input'] injected directly into shell command: ?input=logo.png; cat /etc/passwd
    $input = $_GET['input'];
    system("convert " . $input . " output.jpg");
}

// VULN 2: exec() with archive name and directory both from user-supplied data (Command Injection)
function createOrderArchive($archiveName, $directory) {
    // Both $archiveName and $directory flow from request parameters without escaping
    exec("zip -r " . $archiveName . " " . $directory, $output, $returnCode);
    return ['output' => $output, 'code' => $returnCode];
}

// VULN 3: shell_exec() with file permissions and filename controlled by user (Command Injection)
function setFilePermissions($perms, $file) {
    // chmod command built from two user-controlled variables
    $result = shell_exec("chmod " . $perms . " " . $file);
    return $result;
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'convert') {
    convertProductImage();
} elseif ($action === 'archive') {
    $archiveName = $_POST['archive_name'] ?? 'backup.zip';
    $directory   = $_POST['directory']    ?? '.';
    $result = createOrderArchive($archiveName, $directory);
    echo json_encode($result);
} elseif ($action === 'chmod') {
    $perms = $_POST['perms'] ?? '644';
    $file  = $_POST['file']  ?? '';
    $out   = setFilePermissions($perms, $file);
    echo $out;
}
