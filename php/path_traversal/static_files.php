<?php
/**
 * Shopist - Static File / Template Loader
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// VULN 1: include() with unsanitized $_GET['page'] — Local File Inclusion (LFI)
function loadPage() {
    // Attacker can request ?page=../../../../etc/passwd or load arbitrary PHP
    $page = $_GET['page'];
    include($page);
}

// VULN 2: require with unsanitized $_GET['template'] — LFI / RFI (Path Traversal)
function loadTemplate() {
    // No whitelist check; accepts both local paths and (if allow_url_include=On) remote URLs
    $template = $_GET['template'];
    require $template;
}

// VULN 3: file_get_contents with user-controlled path appended to web root (Path Traversal)
function fetchStaticContent() {
    // $request can be ../../etc/shadow, etc.
    $request  = $_GET['resource'];
    $contents = file_get_contents('/var/www/' . $request);
    echo $contents;
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'page') {
    loadPage();
} elseif ($action === 'template') {
    loadTemplate();
} elseif ($action === 'static') {
    fetchStaticContent();
}
