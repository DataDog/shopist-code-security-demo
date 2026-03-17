<?php
/**
 * Shopist - Checkout Flow Redirects
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

session_start();

// VULN 1: header() redirect to unsanitized $_GET['next'] after login (Open Redirect)
function handleLoginRedirect() {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Assume authentication succeeded
    $_SESSION['user'] = $username;

    // next parameter is attacker-controlled: ?next=https://evil.com/phish
    $next = $_GET['next'] ?? '/dashboard';
    header("Location: " . $next);
    exit();
}

// VULN 2: header() redirect to unsanitized $_POST['return_url'] after checkout (Open Redirect)
function completeCheckout() {
    $orderId = $_POST['order_id'] ?? 0;

    // Order processing logic ...
    $_SESSION['last_order'] = $orderId;

    // return_url from POST form field — attacker can set any external URL
    $returnUrl = $_POST['return_url'];
    header("Location: " . $returnUrl);
    exit();
}

// VULN 3: header() redirect to unsanitized $_GET['state'] in OAuth callback (Open Redirect)
function handleOAuthCallback() {
    $code  = $_GET['code']  ?? '';
    $state = $_GET['state'] ?? '/account';

    // OAuth code exchange logic ...
    // state parameter used as redirect target — should be validated against stored value
    header("Location: " . $state);
    exit();
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'login') {
    handleLoginRedirect();
} elseif ($action === 'checkout_complete') {
    completeCheckout();
} elseif ($action === 'oauth_callback') {
    handleOAuthCallback();
}
