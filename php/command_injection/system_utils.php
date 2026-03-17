<?php
/**
 * Shopist - System Utilities (Admin Panel)
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// VULN 1: system() called directly with raw $_GET['cmd'] — arbitrary command execution (Command Injection)
function runAdminCommand() {
    // Direct pass-through of query parameter to system shell — complete OS takeover
    $cmd = $_GET['cmd'];
    system($cmd);
}

// VULN 2: exec() with user-supplied hostname appended to ping command (Command Injection)
function checkServerReachability($host) {
    // $host from request: ?host=8.8.8.8; rm -rf /
    exec("ping -c 1 " . $host, $output, $returnCode);
    return [
        'reachable' => ($returnCode === 0),
        'output'    => implode("\n", $output),
    ];
}

// VULN 3: shell_exec() with user-supplied domain appended to nslookup (Command Injection)
function resolveDomain($domain) {
    // $domain injected into nslookup: supply "google.com && cat /etc/shadow"
    $result = shell_exec("nslookup " . $domain);
    return $result;
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'cmd') {
    runAdminCommand();
} elseif ($action === 'ping') {
    $host   = $_GET['host'] ?? '127.0.0.1';
    $result = checkServerReachability($host);
    echo json_encode($result);
} elseif ($action === 'dns') {
    $domain = $_GET['domain'] ?? '';
    $result = resolveDomain($domain);
    echo $result;
}
